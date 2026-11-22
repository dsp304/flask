"""
Contract Renewal Watchdog - Alerts Dispatcher (alerts.py)
Task 6: Scheduled / CLI runner for daily contract cancellation deadline alerts.

Workflow:
1. Queries contracts where status = 'active' and calculated_cancellation_deadline IS NOT NULL.
2. Evaluates whether the deadline falls within the workspace vertical's default_alert_lead_days.
3. Checks alert_logs to guarantee notification idempotency (no duplicate alerts for same deadline).
4. Generates formatted summary alerts with vendor spend, risk flags, and immediate action items.
5. Dispatches alerts (logs, optional webhook/email) and persists records to alert_logs.
"""

import os
import sys
import json
import logging
import argparse
import urllib.request
import urllib.error
from datetime import datetime, date, timezone
from typing import Optional, List, Dict, Any

from dotenv import load_dotenv

# Load environment
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("contract_watchdog.alerts")

# Local imports
from db import (
    init_db,
    get_active_contracts_for_alert_scan,
    check_alert_already_sent,
    record_alert_log,
    get_alert_logs,
)
from verticals import VERTICAL_CONFIGS


def format_summary_alert(contract: Dict[str, Any], vertical_config: Dict[str, Any], days_left: int) -> str:
    """
    Format a rich, actionable contract cancellation alert.
    """
    vendor = contract.get("vendor_name") or "Unknown Vendor"
    title = contract.get("contract_title") or "Service Agreement"
    category = contract.get("category") or "General"
    spend = contract.get("annual_spend_estimate")
    spend_str = f"${float(spend):,.2f} USD" if spend is not None else "Unstated"
    deadline = str(contract.get("calculated_cancellation_deadline"))[:10]
    exp_date = str(contract.get("expiration_or_renewal_date") or "N/A")[:10]
    notice_days = contract.get("notice_period_days") or "N/A"
    rollover = contract.get("auto_renewal_term_months")
    rollover_str = f"{rollover} months" if rollover else "Standard evergreen extension"

    # Status / Urgency description
    if days_left < 0:
        urgency_label = f"OVERDUE by {abs(days_left)} days"
    elif days_left <= 15:
        urgency_label = f"CRITICAL: {days_left} days remaining"
    elif days_left <= 30:
        urgency_label = f"ACTION REQUIRED: {days_left} days remaining"
    else:
        urgency_label = f"NOTICE WINDOW OPEN: {days_left} days remaining"

    # Format risk flags
    flags = contract.get("key_risk_flags") or []
    if isinstance(flags, str):
        try:
            flags = json.loads(flags)
        except Exception:
            flags = [flags]
    flags_formatted = "\n".join(f"  - ⚠️ {f}" for f in flags) if flags else "  - None flagged"

    quote = contract.get("source_evidence_quote") or "No quote extracted."

    return f"""================================================================================
🚨 CONTRACT WATCHDOG ALERT: {urgency_label}
================================================================================
Workspace:       {contract.get('workspace_name', 'Default')} (ID: {contract.get('workspace_id')})
Vertical:        {vertical_config.get('display_name', 'General Business')} (Lead Window: {vertical_config.get('default_alert_lead_days', 30)}d)
Vendor:          {vendor}
Agreement:       {title}
Category:        {category}
Annual Spend:    {spend_str}
--------------------------------------------------------------------------------
CANCELLATION DEADLINE: {deadline} ({days_left} days left)
Contract Expiration:   {exp_date}
Notice Period:         {notice_days} days advance written notice required
Auto-Renewal Term:     {rollover_str}
--------------------------------------------------------------------------------
IDENTIFIED RISK FLAGS:
{flags_formatted}

SOURCE EVIDENCE QUOTE:
  "{quote}"

RECOMMENDED IMMEDIATE ACTION:
  Submit formal cancellation/non-renewal notice to {vendor} on or before {deadline}
  to prevent automatic contract rollover at current or escalated rates.
================================================================================
"""


def dispatch_webhook_alert(webhook_url: str, alert_data: Dict[str, Any]) -> bool:
    """
    Dispatch JSON summary payload to Slack/Teams/Discord/Generic Webhook.
    """
    if not webhook_url:
        return False
    try:
        payload = json.dumps({
            "text": alert_data.get("summary"),
            "contract_id": alert_data.get("contract_id"),
            "vendor_name": alert_data.get("vendor_name"),
            "deadline": alert_data.get("deadline"),
            "days_left": alert_data.get("days_left"),
            "workspace_id": alert_data.get("workspace_id"),
            "annual_spend": alert_data.get("annual_spend"),
        }).encode("utf-8")

        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status in (200, 201, 204)
    except Exception as e:
        logger.warning(f"Failed to deliver webhook alert: {e}")
        return False


def run_alert_scan(
    workspace_id: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
    notify_email: Optional[str] = None,
    notify_webhook: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Core Alert Evaluation Engine:
    - Queries active contracts with calculated deadlines.
    - Compares each contract's deadline against its vertical default_alert_lead_days.
    - Enforces idempotency via alert_logs.
    - Dispatches alerts and returns execution summary.
    """
    # Ensure database tables exist
    try:
        init_db()
    except Exception as e:
        logger.warning(f"init_db check during alert scan: {e}")

    webhook_url = notify_webhook or os.environ.get("ALERT_WEBHOOK_URL")
    recipient_email = notify_email or os.environ.get("ALERT_RECIPIENT_EMAIL")

    contracts = get_active_contracts_for_alert_scan(workspace_id=workspace_id)
    today = date.today()

    scanned_count = len(contracts)
    in_window_count = 0
    dispatched_count = 0
    already_alerted_count = 0
    dispatched_records: List[Dict[str, Any]] = []

    logger.info(f"Starting alert scan across {scanned_count} active contract(s) (workspace: {workspace_id or 'ALL'})...")

    for c in contracts:
        contract_id = c["id"]
        c_workspace_id = c["workspace_id"]
        vertical_id = c.get("vertical_id") or "general_b2b"
        vertical_config = VERTICAL_CONFIGS.get(vertical_id, VERTICAL_CONFIGS["general_b2b"])
        lead_days = int(vertical_config.get("default_alert_lead_days", 30))

        deadline_val = c.get("calculated_cancellation_deadline")
        if not deadline_val:
            continue

        if isinstance(deadline_val, str):
            try:
                deadline_date = datetime.strptime(deadline_val[:10], "%Y-%m-%d").date()
            except ValueError:
                continue
        elif isinstance(deadline_val, (date, datetime)):
            deadline_date = deadline_val if isinstance(deadline_val, date) else deadline_val.date()
        else:
            continue

        days_left = (deadline_date - today).days
        deadline_str = deadline_date.strftime("%Y-%m-%d")

        # Check if contract deadline is within the vertical's default_alert_lead_days
        # Note: Also includes overdue contracts (days_left < 0) that have not been logged yet
        if days_left > lead_days:
            continue

        in_window_count += 1

        # Determine alert classification type
        if days_left < 0:
            alert_type = "overdue_notice"
        elif days_left <= 15:
            alert_type = "critical_warning"
        else:
            alert_type = "lead_time_warning"

        # Check alert_logs for idempotency (skip if already notified for this deadline and alert_type)
        if not force and check_alert_already_sent(contract_id, deadline_str, alert_type):
            already_alerted_count += 1
            logger.info(f"Contract #{contract_id} ({c.get('vendor_name')}): Alert '{alert_type}' already sent for deadline {deadline_str}. Skipping.")
            continue

        # Format alert message
        alert_summary = format_summary_alert(c, vertical_config, days_left)

        # Log alert to console/logger
        logger.warning(f"\n{alert_summary}")

        alert_item = {
            "contract_id": contract_id,
            "workspace_id": c_workspace_id,
            "vendor_name": c.get("vendor_name"),
            "contract_title": c.get("contract_title"),
            "alert_type": alert_type,
            "deadline": deadline_str,
            "days_left": days_left,
            "lead_days_window": lead_days,
            "annual_spend": float(c.get("annual_spend_estimate") or 0.0),
            "summary": alert_summary,
            "dry_run": dry_run,
        }

        # Dispatch via Webhook if configured
        if webhook_url and not dry_run:
            delivered = dispatch_webhook_alert(webhook_url, alert_item)
            alert_item["webhook_delivered"] = delivered

        # Record to database alert_logs for audit tracking and idempotency
        if not dry_run:
            success = record_alert_log(
                contract_id=contract_id,
                workspace_id=c_workspace_id,
                calculated_cancellation_deadline=deadline_str,
                days_left=days_left,
                lead_days_window=lead_days,
                alert_summary=alert_summary,
                alert_type=alert_type,
                recipient_email=recipient_email,
            )
            if success:
                dispatched_count += 1
                dispatched_records.append(alert_item)
        else:
            dispatched_count += 1
            dispatched_records.append(alert_item)

    logger.info(
        f"Alert scan complete: Scanned={scanned_count}, InWindow={in_window_count}, "
        f"Dispatched={dispatched_count}, AlreadyLogged={already_alerted_count}, DryRun={dry_run}"
    )

    return {
        "status": "success",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scanned_contracts": scanned_count,
        "contracts_in_window": in_window_count,
        "alerts_dispatched": dispatched_count,
        "already_alerted": already_alerted_count,
        "dry_run": dry_run,
        "alerts": dispatched_records,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Contract Renewal Watchdog - Daily Cancellation Deadline Alert Runner"
    )
    parser.add_argument("--workspace", type=str, default=None, help="Filter to specific workspace_id")
    parser.add_argument("--dry-run", action="store_true", help="Simulate alert scan without recording to alert_logs")
    parser.add_argument("--force", action="store_true", help="Bypass alert_logs deduplication check")
    parser.add_argument("--summary", action="store_true", help="Print audit summary of historical alerts")
    parser.add_argument("--webhook", type=str, default=None, help="Override destination webhook URL")
    parser.add_argument("--email", type=str, default=None, help="Notification email address")

    args = parser.parse_args()

    if args.summary:
        logs = get_alert_logs(workspace_id=args.workspace, limit=20)
        print("\n=== RECENT ALERT AUDIT LOGS ===")
        if not logs:
            print("No alert logs found.")
        else:
            for l in logs:
                print(f"[{l.get('sent_at')}] Contract #{l.get('contract_id')} ({l.get('vendor_name')}) - {l.get('alert_type')}: Deadline {l.get('calculated_cancellation_deadline')} ({l.get('days_left')}d left)")
        sys.exit(0)

    result = run_alert_scan(
        workspace_id=args.workspace,
        dry_run=args.dry_run,
        force=args.force,
        notify_email=args.email,
        notify_webhook=args.webhook,
    )

    print("\n" + json.dumps({
        "status": result["status"],
        "scanned_contracts": result["scanned_contracts"],
        "contracts_in_window": result["contracts_in_window"],
        "alerts_dispatched": result["alerts_dispatched"],
        "already_alerted": result["already_alerted"],
        "dry_run": result["dry_run"],
    }, indent=2))


if __name__ == "__main__":
    main()
