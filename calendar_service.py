"""
Contract Renewal Watchdog - Calendar Reminder Service (calendar_service.py)
Automated calendar reminder creation, Google / Microsoft Calendar syncing,
and RFC 5545 iCalendar (.ics) generation for contracts in critical stages.
"""

import json
import logging
import urllib.parse
from datetime import date, datetime, timedelta
from typing import Optional, Dict, Any, List

logger = logging.getLogger("contract_watchdog.calendar")


def is_contract_in_critical_stage(contract: Dict[str, Any]) -> bool:
    """
    Determine if a contract is currently in the critical deadline stage:
    - calculated_cancellation_deadline is specified, AND
    - days_left <= 45 (within critical lead window), OR
    - urgency is explicitly 'critical' or 'overdue'.
    """
    if not contract:
        return False

    deadline = contract.get("calculated_cancellation_deadline")
    if not deadline:
        return False

    days_left = contract.get("days_left")
    if days_left is None:
        today = date.today()
        if isinstance(deadline, str):
            try:
                deadline_date = datetime.strptime(deadline[:10], "%Y-%m-%d").date()
            except ValueError:
                return False
        elif isinstance(deadline, (datetime, date)):
            deadline_date = deadline if isinstance(deadline, date) else deadline.date()
        else:
            return False

        days_left = (deadline_date - today).days

    urgency = str(contract.get("urgency") or "").lower()
    return days_left <= 45 or urgency in ("critical", "overdue")


def generate_calendar_ics(contract: Dict[str, Any], target_email: str) -> str:
    """
    Generate a standard RFC 5545 iCalendar (.ics) format string for the contract deadline.
    Compatible with Apple Calendar, Google Calendar, Microsoft Outlook, Thunderbird, and mobile devices.
    """
    vendor_name = contract.get("vendor_name") or "Contract Vendor"
    contract_title = contract.get("contract_title") or "Service Agreement"
    contract_id = contract.get("id") or "0"
    
    deadline = contract.get("calculated_cancellation_deadline")
    if isinstance(deadline, (datetime, date)):
        deadline_str = deadline.strftime("%Y%m%d")
        next_day = (deadline + timedelta(days=1)).strftime("%Y%m%d")
        readable_deadline = deadline.strftime("%B %d, %Y")
    elif isinstance(deadline, str) and len(deadline) >= 10:
        clean = deadline[:10].replace("-", "")
        deadline_str = clean
        try:
            dt = datetime.strptime(deadline[:10], "%Y-%m-%d")
            next_day = (dt + timedelta(days=1)).strftime("%Y%m%d")
            readable_deadline = dt.strftime("%B %d, %Y")
        except Exception:
            next_day = clean
            readable_deadline = deadline[:10]
    else:
        today = date.today()
        deadline_str = today.strftime("%Y%m%d")
        next_day = (today + timedelta(days=1)).strftime("%Y%m%d")
        readable_deadline = today.strftime("%B %d, %Y")

    notice_days = contract.get("notice_period_days") or 30
    spend = contract.get("annual_spend_estimate")
    spend_str = f"${spend:,.2f}" if spend else "Not specified"
    how_change = contract.get("how_to_change_summary") or "Refer to service agreement for cancellation instructions."
    flags = contract.get("key_risk_flags") or []
    if isinstance(flags, list):
        flags_text = ", ".join(flags) if flags else "None recorded"
    else:
        flags_text = str(flags)

    now_utc = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    clean_target_email = (target_email or "reminders@contractwatchdog.com").strip().lower()

    description_lines = [
        f"CRITICAL CONTRACT CANCELLATION DEADLINE",
        f"Vendor: {vendor_name}",
        f"Agreement: {contract_title}",
        f"Cancellation Cutoff: {readable_deadline}",
        f"Required Notice Period: {notice_days} days prior to renewal",
        f"Annual Spend: {spend_str}",
        f"Key Risk Flags: {flags_text}",
        f"",
        f"HOW TO CANCEL OR MAKE CHANGES:",
        f"{how_change}",
        f"",
        f"Primary Contact / Recipient: {clean_target_email}",
        f"Automated notification by Contract Renewal Watchdog",
    ]
    description = "\\n".join(description_lines).replace("\r", "")

    ics_content = f"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Contract Renewal Watchdog//Calendar Reminder Service//EN
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VEVENT
UID:contract-reminder-{contract_id}-{deadline_str}@contractwatchdog.com
DTSTAMP:{now_utc}
DTSTART;VALUE=DATE:{deadline_str}
DTEND;VALUE=DATE:{next_day}
SUMMARY:🚨 Contract Cancellation Cutoff: {vendor_name} ({contract_title})
DESCRIPTION:{description}
ORGANIZER;CN=Contract Watchdog:mailto:reminders@contractwatchdog.com
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;CN={clean_target_email}:mailto:{clean_target_email}
STATUS:CONFIRMED
TRANSP:OPAQUE
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:Critical cancellation notice cutoff for {vendor_name} today!
TRIGGER:-P7D
END:VALARM
BEGIN:VALARM
ACTION:DISPLAY
DESCRIPTION:FINAL DAY: Cancellation notice cutoff for {vendor_name} today!
TRIGGER:-PT0M
END:VALARM
END:VEVENT
END:VCALENDAR"""
    return ics_content


def generate_web_calendar_links(contract: Dict[str, Any], target_email: str) -> Dict[str, str]:
    """
    Generate direct one-click URLs to add this contract reminder event
    into Google Calendar and Microsoft 365 / Outlook Web.
    """
    vendor_name = contract.get("vendor_name") or "Contract Vendor"
    contract_title = contract.get("contract_title") or "Agreement"
    contract_id = contract.get("id") or 0
    title = f"🚨 Cancellation Cutoff: {vendor_name} ({contract_title})"

    deadline = contract.get("calculated_cancellation_deadline")
    if isinstance(deadline, (datetime, date)):
        date_raw = deadline.strftime("%Y%m%d")
        next_raw = (deadline + timedelta(days=1)).strftime("%Y%m%d")
        dash_date = deadline.strftime("%Y-%m-%d")
        next_dash_date = (deadline + timedelta(days=1)).strftime("%Y-%m-%d")
    elif isinstance(deadline, str) and len(deadline) >= 10:
        dash_date = deadline[:10]
        date_raw = dash_date.replace("-", "")
        try:
            dt = datetime.strptime(dash_date, "%Y-%m-%d")
            next_raw = (dt + timedelta(days=1)).strftime("%Y%m%d")
            next_dash_date = (dt + timedelta(days=1)).strftime("%Y-%m-%d")
        except Exception:
            next_raw = date_raw
            next_dash_date = dash_date
    else:
        today = date.today()
        dash_date = today.strftime("%Y-%m-%d")
        date_raw = today.strftime("%Y%m%d")
        next_raw = (today + timedelta(days=1)).strftime("%Y%m%d")
        next_dash_date = (today + timedelta(days=1)).strftime("%Y-%m-%d")

    notice = contract.get("notice_period_days") or 30
    spend = contract.get("annual_spend_estimate")
    spend_text = f"${spend:,.2f}" if spend else "N/A"
    how_change = contract.get("how_to_change_summary") or "Submit formal notice in writing."

    details = (
        f"CRITICAL CONTRACT CANCELLATION DEADLINE\n"
        f"Vendor: {vendor_name}\n"
        f"Agreement: {contract_title}\n"
        f"Notice Required: {notice} days\n"
        f"Annual Spend: {spend_text}\n\n"
        f"HOW TO CANCEL OR AMEND:\n{how_change}\n\n"
        f"Primary User Email: {target_email}\n"
        f"Monitored by Contract Renewal Watchdog"
    )

    google_url = (
        f"https://calendar.google.com/calendar/render?action=TEMPLATE&"
        f"text={urllib.parse.quote(title)}&"
        f"dates={date_raw}/{next_raw}&"
        f"details={urllib.parse.quote(details)}&"
        f"add={urllib.parse.quote(target_email or '')}"
    )

    outlook_url = (
        f"https://outlook.live.com/calendar/0/deeplink/compose?"
        f"subject={urllib.parse.quote(title)}&"
        f"body={urllib.parse.quote(details)}&"
        f"startdt={dash_date}T09:00:00&enddt={dash_date}T10:00:00"
    )

    return {
        "google": google_url,
        "outlook": outlook_url,
        "ics": f"/contracts/{contract_id}/calendar.ics",
    }


def setup_calendar_reminder_for_contract(
    contract_id: int,
    target_email: str,
    workspace_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Setup a calendar reminder for a specific contract:
    1. Validates contract exists and has a cancellation deadline.
    2. Syncs with live Google / Microsoft Calendar API if OAuth connection exists.
    3. Persists calendar reminder setup timestamp, target email, and status to the database.
    4. Logs setup event for transparency.
    """
    from db import get_contract, update_contract_calendar_reminder, get_oauth_connection

    contract = get_contract(contract_id)
    if not contract:
        logger.warning(f"Contract #{contract_id} not found for calendar reminder setup.")
        return {"success": False, "error": "Contract not found"}

    deadline = contract.get("calculated_cancellation_deadline")
    if not deadline:
        logger.warning(f"Contract #{contract_id} has no calculated cancellation deadline; cannot set calendar reminder.")
        return {"success": False, "error": "No cancellation deadline found"}

    clean_email = (target_email or "").strip().lower()
    if not clean_email or "@" not in clean_email:
        clean_email = contract.get("sender_email") or "primary@contractwatchdog.com"

    ws_id = workspace_id or contract.get("workspace_id")
    api_sync_status = "simulated"

    # Attempt Live API Sync if workspace has active Google or Microsoft OAuth connection
    if ws_id:
        try:
            google_conn = get_oauth_connection(ws_id, "google")
            if google_conn and google_conn.get("access_token"):
                import urllib.request
                access_token = google_conn["access_token"]
                logger.info(f"Attempting live Google Calendar API event creation for contract #{contract_id}...")
                
                # Format dates
                if isinstance(deadline, (datetime, date)):
                    start_str = deadline.strftime("%Y-%m-%d")
                    end_str = (deadline + timedelta(days=1)).strftime("%Y-%m-%d")
                else:
                    start_str = str(deadline)[:10]
                    end_str = start_str

                event_payload = {
                    "summary": f"🚨 Contract Cancellation Cutoff: {contract.get('vendor_name')} ({contract.get('contract_title')})",
                    "description": contract.get("how_to_change_summary") or "Contract cancellation deadline reminder.",
                    "start": {"date": start_str},
                    "end": {"date": end_str},
                    "attendees": [{"email": clean_email}],
                    "reminders": {
                        "useDefault": False,
                        "overrides": [
                            {"method": "email", "minutes": 1440},
                            {"method": "popup", "minutes": 1440},
                        ],
                    },
                }

                req = urllib.request.Request(
                    "https://www.googleapis.com/calendar/v3/calendars/primary/events",
                    data=json.dumps(event_payload).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        if resp.status in (200, 201):
                            api_sync_status = "google_synced"
                            logger.info(f"Live Google Calendar event created for contract #{contract_id}.")
                except Exception as gcal_err:
                    logger.info(f"Live Google Calendar API call note (using standard calendar invite fallback): {gcal_err}")

            # Also check Microsoft Graph Calendar API connection
            ms_conn = get_oauth_connection(ws_id, "microsoft")
            if api_sync_status == "simulated" and ms_conn and ms_conn.get("access_token"):
                access_token = ms_conn["access_token"]
                logger.info(f"Attempting live Microsoft Calendar API event creation for contract #{contract_id}...")
                if isinstance(deadline, (datetime, date)):
                    date_str = deadline.strftime("%Y-%m-%d")
                else:
                    date_str = str(deadline)[:10]

                ms_event_payload = {
                    "subject": f"🚨 Contract Cancellation Cutoff: {contract.get('vendor_name')} ({contract.get('contract_title')})",
                    "body": {
                        "contentType": "Text",
                        "content": contract.get("how_to_change_summary") or "Contract cancellation deadline reminder."
                    },
                    "start": {
                        "dateTime": f"{date_str}T09:00:00",
                        "timeZone": "UTC"
                    },
                    "end": {
                        "dateTime": f"{date_str}T10:00:00",
                        "timeZone": "UTC"
                    },
                    "reminderMinutesBeforeStart": 1440,
                    "isReminderOn": True
                }
                ms_req = urllib.request.Request(
                    "https://graph.microsoft.com/v1.0/me/events",
                    data=json.dumps(ms_event_payload).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                try:
                    with urllib.request.urlopen(ms_req, timeout=5) as resp:
                        if resp.status in (200, 201):
                            api_sync_status = "microsoft_synced"
                            logger.info(f"Live Microsoft Calendar event created for contract #{contract_id}.")
                except Exception as mscal_err:
                    logger.info(f"Live Microsoft Calendar API call note: {mscal_err}")
        except Exception as oauth_err:
            logger.debug(f"OAuth check notice: {oauth_err}")

    # Persist calendar reminder setup to database
    now_dt = datetime.now()
    success = update_contract_calendar_reminder(
        contract_id=contract_id,
        target_email=clean_email,
        reminder_date=deadline,
        reminder_status=api_sync_status,
        reminder_set_at=now_dt,
    )

    formatted_time = now_dt.strftime("%b %d, %Y at %I:%M %p")
    logger.info(
        f"Calendar reminder successfully setup for Contract #{contract_id} ({contract.get('vendor_name')}): "
        f"Target Email={clean_email}, Setup At={formatted_time}, Status={api_sync_status}"
    )

    return {
        "success": success,
        "contract_id": contract_id,
        "target_email": clean_email,
        "reminder_set_at": now_dt,
        "reminder_set_at_display": formatted_time,
        "status": api_sync_status,
        "deadline": str(deadline),
    }


def auto_setup_critical_contract_calendar_reminders(
    workspace_id: str,
    primary_login_email: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Automated watchdog scanner for critical stage contracts:
    Iterates through active contracts in the workspace.
    For each contract in the critical stage (days_left <= 45 or urgency critical/overdue),
    automatically sets up the calendar reminder for the primary login email
    if not already set, or if the primary login email was updated.
    """
    if not workspace_id:
        return []

    from db import get_dashboard_contracts

    clean_email = (primary_login_email or "").strip().lower()
    if not clean_email or "@" not in clean_email or clean_email.startswith("demo@"):
        clean_email = primary_login_email or "admin@contractwatchdog.com"

    try:
        active_contracts, _ = get_dashboard_contracts(workspace_id)
    except Exception as e:
        logger.warning(f"Error fetching active contracts for calendar reminder setup: {e}")
        return []

    scheduled_results = []
    for c in active_contracts:
        if not is_contract_in_critical_stage(c):
            continue

        contract_id = c.get("id")
        if not contract_id:
            continue

        already_set = bool(c.get("calendar_reminder_set"))
        has_set_at = bool(c.get("calendar_reminder_set_at"))
        current_target = (c.get("calendar_reminder_target_email") or "").strip().lower()

        # Needs setup if not set yet, or if user is logged in with a real email that differs from generic test account
        needs_setup = False
        if not already_set or not has_set_at:
            needs_setup = True
        elif clean_email and "@" in clean_email and not clean_email.startswith("demo@") and current_target in ("demo@contractwatchdog.com", "user@workspace.com", ""):
            # Sync target email to the newly logged-in user!
            needs_setup = True

        if needs_setup:
            res = setup_calendar_reminder_for_contract(
                contract_id=contract_id,
                target_email=clean_email,
                workspace_id=workspace_id,
            )
            if res.get("success"):
                scheduled_results.append(res)

    if scheduled_results:
        logger.info(f"Auto-scheduled {len(scheduled_results)} calendar reminder(s) for workspace '{workspace_id}' (email: {clean_email}).")

    return scheduled_results
