import re
import io
import html
import base64
import hashlib
import logging
from typing import Optional, List, Dict, Any, Tuple
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Try importing fitz (PyMuPDF)
try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None
    logger.warning("PyMuPDF (fitz) is not installed. PDF text extraction will be disabled.")

# Try importing docx (python-docx)
try:
    import docx
except ImportError:
    docx = None
    logger.warning("python-docx is not installed. DOCX text extraction will be disabled.")


# ---------------------------------------------------------------------------
# HTML Email Cleaning
# ---------------------------------------------------------------------------
def clean_html_body(html_content: str) -> str:
    """
    Strip scripts, styling, navigation, and markup from HTML email body.
    Converts block breaks into line breaks and normalizes whitespace.
    """
    if not html_content or not html_content.strip():
        return ""

    soup = BeautifulSoup(html_content, "html.parser")

    # Remove non-content elements
    for element in soup(["script", "style", "head", "meta", "link", "noscript", "svg", "button", "input"]):
        element.decompose()

    # Insert explicit newlines before block elements to prevent words running together
    for tag in soup.find_all(["br", "p", "div", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6"]):
        tag.append(" \n")

    # Extract text and unescape HTML entities (&amp;, &nbsp;, etc.)
    text = soup.get_text(separator=" ")
    text = html.unescape(text)

    # Normalize excessive blank lines and spaces
    lines = [line.strip() for line in text.splitlines()]
    cleaned_lines = []
    blank_count = 0
    for line in lines:
        if not line:
            blank_count += 1
            if blank_count <= 2:
                cleaned_lines.append("")
        else:
            blank_count = 0
            cleaned_lines.append(line)

    return "\n".join(cleaned_lines).strip()


# ---------------------------------------------------------------------------
# Reply Chain & Quoted Text Stripping
# ---------------------------------------------------------------------------
REPLY_CHAIN_PATTERNS = [
    # "On Jan 1, 2025, at 10:00 AM, John Doe <john@example.com> wrote:"
    re.compile(r"(?im)^\s*On\s+.+?(?:wrote|wrote\s*:)\s*$", re.MULTILINE),
    # "-----Original Message-----"
    re.compile(r"(?im)^\s*-{3,}\s*Original Message\s*-{3,}", re.MULTILINE),
    # "________________________________" (Horizontal separator line)
    re.compile(r"(?im)^\s*_{10,}\s*$", re.MULTILINE),
    # "--------------------------------"
    re.compile(r"(?im)^\s*-{10,}\s*$", re.MULTILINE),
    # Outlook header block: From: ... Sent: ... To: ... Subject: ...
    re.compile(r"(?im)^\s*From:\s+.*?\n\s*(?:Sent|Date):\s+.*?\n\s*(?:To|Subject):\s+", re.MULTILINE),
    # Internationalized reply headers (French, German)
    re.compile(r"(?im)^\s*De\s*:\s+.*?\n\s*Envoyé\s*:", re.MULTILINE),
    re.compile(r"(?im)^\s*Von\s*:\s+.*?\n\s*Gesendet\s*:", re.MULTILINE),
]

DISCLAIMER_PATTERNS = [
    re.compile(r"(?im)^\s*Sent from my (?:iPhone|iPad|Android|Galaxy).*?$", re.MULTILINE),
    re.compile(r"(?im)^\s*Get Outlook for (?:iOS|Android).*?$", re.MULTILINE),
]


def strip_reply_chains(text: str) -> str:
    """
    Remove quoted email history (replies, forwards, 'On ... wrote:', headers)
    and standard mobile signatures to isolate the primary message content.
    """
    if not text or not text.strip():
        return ""

    cut_index = len(text)

    # Find the earliest occurrence of a standard reply chain delimiter
    for pattern in REPLY_CHAIN_PATTERNS:
        match = pattern.search(text)
        if match and match.start() > 20:  # Avoid truncating if pattern is at very top
            if match.start() < cut_index:
                cut_index = match.start()

    primary_text = text[:cut_index].strip()

    # Filter out lines starting with '>' (classic quoted lines)
    filtered_lines = []
    for line in primary_text.splitlines():
        trimmed = line.strip()
        if trimmed.startswith(">"):
            continue
        filtered_lines.append(line)

    result = "\n".join(filtered_lines).strip()

    # Remove standard mobile device footers
    for pattern in DISCLAIMER_PATTERNS:
        result = pattern.sub("", result)

    return result.strip()


# ---------------------------------------------------------------------------
# Attachment Text Extraction (PDF & DOCX)
# ---------------------------------------------------------------------------
def extract_text_from_pdf(pdf_bytes: bytes, max_pages: int = 50) -> str:
    """
    Extract readable text from PDF bytes using PyMuPDF (fitz).
    """
    if fitz is None:
        logger.error("fitz (PyMuPDF) is not installed; cannot extract PDF text.")
        return ""

    if not pdf_bytes:
        return ""

    extracted_pages = []
    try:
        with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
            page_limit = min(len(doc), max_pages)
            for page_index in range(page_limit):
                page = doc[page_index]
                text = page.get_text("text")
                if text and text.strip():
                    extracted_pages.append(f"--- Page {page_index + 1} ---\n{text.strip()}")
        return "\n\n".join(extracted_pages)
    except Exception as e:
        logger.warning(f"Failed to extract text from PDF: {e}")
        return ""


def extract_text_from_docx(docx_bytes: bytes) -> str:
    """
    Extract readable text from DOCX bytes using python-docx.
    Extracts both paragraph bodies and tables.
    """
    if docx is None:
        logger.error("python-docx is not installed; cannot extract DOCX text.")
        return ""

    if not docx_bytes:
        return ""

    extracted_parts = []
    try:
        doc = docx.Document(io.BytesIO(docx_bytes))
        
        # Paragraphs
        for paragraph in doc.paragraphs:
            text = paragraph.text.strip()
            if text:
                extracted_parts.append(text)

        # Tables (contracts often place pricing/dates inside tables)
        for table in doc.tables:
            for row in table.rows:
                row_cells = [cell.text.strip() for cell in row.cells if cell.text.strip()]
                if row_cells:
                    # Deduplicate contiguous duplicate cells from merged columns
                    unique_cells = []
                    for c in row_cells:
                        if not unique_cells or unique_cells[-1] != c:
                            unique_cells.append(c)
                    extracted_parts.append(" | ".join(unique_cells))

        return "\n".join(extracted_parts)
    except Exception as e:
        logger.warning(f"Failed to extract text from DOCX: {e}")
        return ""


# ---------------------------------------------------------------------------
# Postmark Inbound Payload Parser
# ---------------------------------------------------------------------------
def parse_inbound_email(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parse a Postmark-style inbound email JSON payload:
    1. Extract sender, recipient, subject.
    2. Clean HTML body or text body and strip reply chains.
    3. Decode and extract text from supported attachments (PDF, DOCX).
    4. Combine email body + attachments into a single context document.
    5. Compute a deterministic SHA-256 content_hash.
    """
    # 1. Sender extraction
    from_full = payload.get("FromFull") or {}
    sender_email = from_full.get("Email") or payload.get("From", "")
    # Clean email address if in "Name <email@domain.com>" format
    email_match = re.search(r"<([^>]+)>", sender_email)
    if email_match:
        sender_email = email_match.group(1).strip()
    
    sender_name = from_full.get("Name") or payload.get("FromName", "")
    subject = (payload.get("Subject") or "").strip()

    # 2. Body extraction & cleaning
    html_body = payload.get("HtmlBody") or ""
    text_body = payload.get("TextBody") or ""

    if html_body:
        cleaned_body = clean_html_body(html_body)
    else:
        cleaned_body = text_body.strip()

    # Strip quoted replies and history
    primary_body = strip_reply_chains(cleaned_body)

    # 3. Process Attachments
    attachments = payload.get("Attachments") or []
    attachment_texts: List[str] = []
    processed_attachment_names: List[str] = []

    for att in attachments:
        filename = att.get("Name", "attachment")
        content_b64 = att.get("Content", "")
        content_type = (att.get("ContentType") or "").lower()

        if not content_b64:
            continue

        try:
            raw_bytes = base64.b64decode(content_b64)
        except Exception as e:
            logger.warning(f"Failed to base64-decode attachment '{filename}': {e}")
            continue

        filename_lower = filename.lower()
        extracted_text = ""

        # Check for PDF
        if filename_lower.endswith(".pdf") or "pdf" in content_type:
            extracted_text = extract_text_from_pdf(raw_bytes)
        # Check for DOCX
        elif filename_lower.endswith(".docx") or "wordprocessingml" in content_type:
            extracted_text = extract_text_from_docx(raw_bytes)
        # Check for plain text attachment
        elif filename_lower.endswith(".txt") or "text/plain" in content_type:
            try:
                extracted_text = raw_bytes.decode("utf-8", errors="replace").strip()
            except Exception:
                extracted_text = ""

        if extracted_text and extracted_text.strip():
            processed_attachment_names.append(filename)
            attachment_texts.append(
                f"=== ATTACHMENT: {filename} ===\n{extracted_text.strip()}"
            )

    # 4. Synthesize Combined Text
    sections = []
    if primary_body:
        sections.append(f"EMAIL SUBJECT: {subject}\nFROM: {sender_name} <{sender_email}>\n\nEMAIL BODY:\n{primary_body}")
    elif subject:
        sections.append(f"EMAIL SUBJECT: {subject}\nFROM: {sender_name} <{sender_email}>")

    if attachment_texts:
        sections.extend(attachment_texts)

    combined_text = "\n\n".join(sections).strip()

    # 5. Deterministic Content Hash (SHA-256)
    content_hash = hashlib.sha256(combined_text.encode("utf-8")).hexdigest()
    primary_attachment = processed_attachment_names[0] if processed_attachment_names else None

    return {
        "sender_email": sender_email,
        "sender_name": sender_name,
        "subject": subject,
        "cleaned_body": primary_body,
        "attachment_names": processed_attachment_names,
        "primary_attachment_filename": primary_attachment,
        "combined_text": combined_text,
        "content_hash": content_hash,
    }
