import os
import time
from typing import Optional, List
from pydantic import BaseModel, Field
from google import genai
from google.genai import types
from verticals import VERTICAL_CONFIGS

# Lazy initialization of Gemini client to prevent app boot crashes when API key is pending
_client: Optional[genai.Client] = None

def get_genai_client() -> genai.Client:
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY environment variable is not set. "
                "Please configure a valid Google AI Studio API key in Railway."
            )
        _client = genai.Client(api_key=api_key)
    return _client

class ContractExtractionResult(BaseModel):
    is_valid_contract_or_renewal: bool = Field(
        description="True if actual vendor contract, lease, renewal notice, or COI. False if marketing spam or receipt."
    )
    vendor_name: str = Field(description="Normalized legal or common brand name of vendor.")
    contract_title: str = Field(description="Short descriptive title of agreement.")
    category: str = Field(description="Must match one of the allowed categories for the vertical.")
    expiration_or_renewal_date: Optional[str] = Field(None, description="ISO-8601 date (YYYY-MM-DD).")
    notice_period_days: Optional[int] = Field(None, description="Days prior to expiration required for notice.")
    calculated_cancellation_deadline: Optional[str] = Field(None, description="ISO-8601 date (YYYY-MM-DD).")
    auto_renewal_term_months: Optional[int] = Field(None, description="Auto-renewal extension in months.")
    annual_spend_estimate: Optional[float] = Field(None, description="Annualized dollar value numeric.")
    currency: str = Field("USD", description="3-letter ISO currency code.")
    price_escalation_summary: Optional[str] = Field(None, description="Summary of price increase or CPI escalator.")
    how_to_change_summary: Optional[str] = Field(None, description="Detailed instructions on how to make changes, amend, or cancel/terminate the contract (e.g. certified mail requirement, email address, notice cutoff window, designated contact).")
    coi_or_compliance_expiry: Optional[str] = Field(None, description="ISO-8601 date if COI or insurance expires.")
    key_risk_flags: List[str] = Field(default_factory=list, description="Critical risk bullet points.")
    source_evidence_quote: str = Field(description="Verbatim sentence proving dates or terms.")
    confidence_score: float = Field(description="Float between 0.0 and 1.0.")
    is_cancellation_or_termination: bool = Field(
        default=False,
        description="True if this email/document is a notice of contract cancellation, non-renewal declaration, service termination confirmation, or intent not to renew."
    )
    cancellation_reason: Optional[str] = Field(
        default=None,
        description="Reason or explanation for contract cancellation/non-renewal if mentioned in the notice."
    )

def is_cancellation_message(subject: str = "", text: str = "") -> bool:
    """
    Deterministic rule-based check to verify if email subject or text indicates contract cancellation / non-renewal.
    """
    combined = f"{subject or ''} {text or ''}".lower()
    cancellation_indicators = [
        "cancellation notice",
        "notice of cancellation",
        "non-renewal notice",
        "notice of non-renewal",
        "non renewal notice",
        "intent not to renew",
        "terminating agreement",
        "termination of agreement",
        "notice of termination",
        "contract cancelled",
        "contract terminated",
        "agreement cancelled",
        "agreement terminated",
        "service termination",
        "subscription cancelled",
        "discontinue service",
        "service discontinuation",
        "do not renew",
    ]
    return any(ind in combined for ind in cancellation_indicators)

def extract_contract_from_text(raw_text: str, vertical_id: str = "general_b2b") -> ContractExtractionResult:
    config = VERTICAL_CONFIGS.get(vertical_id, VERTICAL_CONFIGS["general_b2b"])
    
    system_prompt = f"""
You are an expert B2B contract analyst and procurement risk intelligence assistant. Inspect raw email bodies or agreement text and extract structured renewal, cancellation, pricing, and compliance metadata.

STRICT RULES:
1. NEVER GUESS DATES: If unstated, set date fields to null and lower confidence_score below 0.65.
2. CALCULATE DEADLINES: Subtract notice_period_days from expiration_or_renewal_date accurately.
3. HOW TO MAKE CHANGES: Extract specific instructions on how to make changes, amend, or terminate/cancel the contract (e.g., written notice via certified mail, notice address, designated email, notice window).
4. CONFIDENCE SCORING: Score >= 0.85 only when vendor and dates are explicit.
5. CANCELLATION & NON-RENEWAL: If this message represents a cancellation notice, non-renewal declaration, contract termination notice, or discontinuation of service, set is_cancellation_or_termination=true and describe cancellation_reason.

{config['llm_domain_hints']}
ALLOWED CATEGORIES: {config['categories']}
"""

    client = get_genai_client()
    last_err = None
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model='gemini-3.5-flash-lite',
                contents=f"Analyze the following contract/email text:\n\n{raw_text}",
                config=types.GenerateContentConfig(
                    system_instruction=system_prompt,
                    response_mime_type="application/json",
                    response_schema=ContractExtractionResult,
                    temperature=0.1
                ),
            )
            # Pydantic structured output returned directly in response.parsed
            return response.parsed
        except Exception as e:
            last_err = e
            err_msg = str(e)
            if attempt < 2 and any(code in err_msg for code in ("503", "429", "UNAVAILABLE", "RESOURCE_EXHAUSTED")):
                time.sleep(1.5 * (attempt + 1))
                continue
            raise last_err
