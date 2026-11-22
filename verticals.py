"""
Vertical Configurations for Contract Renewal Watchdog.
Contains domain-specific keyword dictionaries, LLM review guidelines,
and tailored landing page configurations for Task 5.
"""

VERTICAL_CONFIGS = {
    "property_mgmt": {
        "display_name": "Property Management",
        "route_path": "/property-management",
        "default_alert_lead_days": 45,
        "headline": "Never Get Trapped in a 36-Month Waste or Elevator Auto-Renewal Again",
        "subheadline": "Contract intelligence built specifically for commercial and multifamily property managers. Catch hidden 60-day certified mail notice clauses, track silent CPI escalations, and monitor expiring vendor COIs automatically.",
        "roi_hook": "Save $14,000+ per property by catching silent multi-year rollovers on commercial waste hauling, elevator maintenance, and HVAC service agreements.",
        "trust_strip": "Trusted by property management teams overseeing 4.2M+ sq. ft. of commercial & residential real estate.",
        "trust_badges": ["Colliers Alliance", "CBRE Portfolio Compatible", "BOMA Partner", "WasteWise Certified", "COI Tracking Active"],
        "cta_text": "Protect Your Properties Now",
        "stat_metric": "$14,400",
        "stat_label": "Average Evergreen Trap Cost Avoided",
        "traps_highlighted": [
            {
                "title": "Certified Mail Cancellation Traps",
                "desc": "Commercial waste-hauling and elevator vendors frequently demand physical certified mail 60 to 90 days prior to contract expiration, or auto-renew for 24–36 months.",
            },
            {
                "title": "Uncapped CPI & Fuel Escalators",
                "desc": "Silent 4% to 8% annual compounding CPI, fuel, and environmental fee increases slipped into service terms that inflate operating expenses.",
            },
            {
                "title": "Vendor Liability & COI Expiration",
                "desc": "Unmonitored vendor insurance (ACORD 25) expiring mid-contract exposes property owners to massive third-party liability claims.",
            },
        ],
        "categories": [
            "Waste & Recycling",
            "HVAC & Mechanical",
            "Landscaping & Snow Removal",
            "Elevator & Fire Safety",
            "Security & Janitorial",
            "Property Insurance & COI",
            "Other Property Vendor",
        ],
        "search_keywords": [
            "renewal", "auto-renew", "notice period", "waste", "hauling",
            "HVAC", "snow removal", "landscaping", "elevator", "fire alarm",
            "certificate of insurance", "COI", "service agreement", "CPI"
        ],
        "llm_domain_hints": """
ACTIVE VERTICAL: Property Management
ALLOWED CATEGORIES: ["Waste & Recycling", "HVAC & Mechanical", "Landscaping & Snow Removal", "Elevator & Fire Safety", "Security & Janitorial", "Property Insurance & COI", "Other Property Vendor"]
INDUSTRY TRAPS TO PRIORITIZE:
- Commercial waste-hauling and elevator agreements frequently hide 60-to-90-day written cancellation windows (often requiring certified mail) and auto-renew for 12 to 36 months.
- Watch closely for annual CPI (Consumer Price Index), fuel, or environmental fee escalators.
- If the document is a Certificate of Insurance (COI / ACORD 25) or mentions vendor liability insurance expiration, extract the policy expiration date into `coi_or_compliance_expiry`.
""",
    },

    "dental_medical": {
        "display_name": "Dental & Medical Clinics",
        "route_path": "/dental-clinics",
        "default_alert_lead_days": 60,
        "headline": "Stop Overpaying on Imaging Leases & Medical Waste Auto-Rollovers",
        "subheadline": "Automated contract watchdog for dentists, surgeons, and medical practices. Track CBCT imaging systems, autoclave service, EMR subscriptions, and biohazard pickups before strict buyout notice windows close.",
        "roi_hook": "Eliminate $18,500 in unwanted 12-month equipment lease rollovers and avoid predatory practice management termination penalties.",
        "trust_strip": "Safeguarding 250+ private practices, orthodontists, and dental service organizations nationwide.",
        "trust_badges": ["Henry Schein Verified", "Patterson Lease Verified", "HIPAA-Safe Architecture", "Biohazard Watchlist", "ADA Vendor Compatible"],
        "cta_text": "Protect Your Practice Now",
        "stat_metric": "$18,500",
        "stat_label": "Avg. Saved Per Equipment Lease Buyout",
        "traps_highlighted": [
            {
                "title": "Strict Equipment Buyout Windows",
                "desc": "Dental chair and CBCT imaging leases (Planmeca, Carestream, Dentsply) require 90–120 days advance notice to return or buy out, or automatically extend for 12 months at full payment.",
            },
            {
                "title": "Biohazard Evergreen Extensions",
                "desc": "Medical and biohazard waste contracts enforce multi-year evergreen rollovers with steep liquidated damages penalties for early exit.",
            },
            {
                "title": "EMR Data-Hostage Penalties",
                "desc": "Practice management and clinical EMR software vendors imposing surprise multi-thousand dollar data migration fees upon system replacement.",
            },
        ],
        "categories": [
            "Practice Mgmt & EMR Software",
            "Imaging & Chair Equipment Leases",
            "Biohazard & Medical Waste",
            "Lab & Clinical Supplies",
            "Linen & Sterilization",
            "IT & Managed Support",
            "Other Clinic Vendor",
        ],
        "search_keywords": [
            "renewal", "lease", "buyout", "EMR", "practice management",
            "imaging", "biohazard", "medical waste", "Henry Schein",
            "Patterson", "sterilization", "auto-renew", "notice period"
        ],
        "llm_domain_hints": """
ACTIVE VERTICAL: Dental & Medical Clinics
ALLOWED CATEGORIES: ["Practice Mgmt & EMR Software", "Imaging & Chair Equipment Leases", "Biohazard & Medical Waste", "Lab & Clinical Supplies", "Linen & Sterilization", "IT & Managed Support", "Other Clinic Vendor"]
INDUSTRY TRAPS TO PRIORITIZE:
- Dental chair, CBCT/X-ray imaging, and sterilization equipment leases frequently require 60-to-120-day written notice prior to lease end to exercise a buyout or return, otherwise auto-extending for 12 months.
- Biohazard/medical waste contracts often contain steep annual rate escalators and multi-year evergreen rollovers.
- Flag any EMR/practice management software data-export fees or termination penalties in `key_risk_flags`.
""",
    },

    "msp_it": {
        "display_name": "MSPs & IT Agencies",
        "route_path": "/msp",
        "default_alert_lead_days": 30,
        "headline": "Protect Your Agency Margins from Unused SaaS Seats & Circuit Rollovers",
        "subheadline": "Contract intelligence tailored for Managed Service Providers. Never get blindsided by upstream cloud vendor true-ups, wholesale price spikes, or 36-month telecom fiber circuit auto-renewals.",
        "roi_hook": "Recover 8–15% gross margin by eliminating zombie SaaS licenses and catching 30-day notice cutoffs before annual true-up commits.",
        "trust_strip": "Active contract vigilance for 180+ MSPs, MSSPs, and IT cloud consultancies.",
        "trust_badges": ["ConnectWise Ecosystem", "Kaseya & Datto Compatible", "SOC 2 Type II Encrypted", "Channel Futures Recognized", "B2B SaaS Ready"],
        "cta_text": "Secure Your Agency Margins",
        "stat_metric": "12.4%",
        "stat_label": "Average Gross Margin Recovered",
        "traps_highlighted": [
            {
                "title": "Annual Seat Commit True-Ups",
                "desc": "Upstream security and cloud SaaS vendors locking your agency into peak seat counts for 12 months without downward flexibility.",
            },
            {
                "title": "Telecom Circuit 36-Month Rollovers",
                "desc": "Fiber and SIP trunk contracts carrying brutal early termination fees (ETFs) if notice isn't delivered in a narrow 60-day window.",
            },
            {
                "title": "Upstream Wholesale Price Increases",
                "desc": "Silent 10–15% vendor price hikes slipped into monthly billing statements that eat your client margin unless contested early.",
            },
        ],
        "categories": [
            "Upstream Cloud & SaaS",
            "Security & Backup Tools",
            "Telecom & ISP Circuits",
            "Client MSAs & Retainers",
            "Hardware & Warranties",
            "Other IT Vendor",
        ],
        "search_keywords": [
            "renewal", "MSA", "master service agreement", "seat commitment",
            "circuit", "fiber", "telecom", "true-up", "annual commit",
            "price increase", "auto-renew", "subscription"
        ],
        "llm_domain_hints": """
ACTIVE VERTICAL: MSPs & IT Agencies
ALLOWED CATEGORIES: ["Upstream Cloud & SaaS", "Security & Backup Tools", "Telecom & ISP Circuits", "Client MSAs & Retainers", "Hardware & Warranties", "Other IT Vendor"]
INDUSTRY TRAPS TO PRIORITIZE:
- Flag minimum seat commitments, annual spend commits, and automatic seat true-up clauses.
- Telecom, SIP trunk, and fiber circuit contracts frequently carry 36-to-60-month terms with 60-to-90-day termination windows and early termination fees (ETFs).
- Highlight upstream vendor wholesale price increases or legacy tier sunsets.
""",
    },

    "logistics_mfg": {
        "display_name": "Logistics & Light Manufacturing",
        "route_path": "/logistics",
        "default_alert_lead_days": 45,
        "headline": "Eliminate Surprise Forklift Extension Fees & Expiring Freight Rate Tables",
        "subheadline": "Contract watchdog built for distribution centers, third-party logistics, and manufacturing plants. Catch strict equipment return deadlines, pallet wrapper leases, and carrier fuel surcharge hikes.",
        "roi_hook": "Prevent $24,000 in unexpected forklift month-to-month penalties and keep freight rate tables locked in ahead of expiration.",
        "trust_strip": "Defending 95+ distribution centers, 3PL facilities, and manufacturing plants across North America.",
        "trust_badges": ["WERC Compliant", "OSHA Fleet Safeguard", "SupplyChain 24/7 Verified", "MHI Partner Network", "FreightWatch Active"],
        "cta_text": "Review Your Plant Leases Now",
        "stat_metric": "$24,000",
        "stat_label": "Avg. Penalty Avoided Per Fleet Renewal",
        "traps_highlighted": [
            {
                "title": "Strict Return Inspection Clauses",
                "desc": "Forklift and material handling equipment leases requiring 60–90 days advance return notice and stringent condition standards before automatic 12-month extensions trigger.",
            },
            {
                "title": "Carrier Rate Table Sunset Dates",
                "desc": "Expiring freight tariffs and contract rates that quietly revert to elevated spot pricing with punishing fuel surcharges without warning.",
            },
            {
                "title": "Minimum Volume Clawbacks",
                "desc": "Packaging and raw material vendor agreements that penalize your plant or claw back volume discounts if quarterly throughput dips.",
            },
        ],
        "categories": [
            "Fleet & Forklift Leases",
            "Freight & Carrier Rates",
            "Packaging & Raw Materials",
            "Facility & Utilities",
            "Warehouse & ERP Software",
            "Other Operations Vendor",
        ],
        "search_keywords": [
            "renewal", "forklift", "fleet", "equipment lease", "return notice",
            "carrier", "rate table", "tariff", "fuel surcharge", "packaging",
            "minimum volume", "auto-renew"
        ],
        "llm_domain_hints": """
ACTIVE VERTICAL: Logistics & Light Manufacturing
ALLOWED CATEGORIES: ["Fleet & Forklift Leases", "Freight & Carrier Rates", "Packaging & Raw Materials", "Facility & Utilities", "Warehouse & ERP Software", "Other Operations Vendor"]
INDUSTRY TRAPS TO PRIORITIZE:
- Forklift, pallet wrapper, and fleet leases often require strict advance return notices (60-90 days) and specific return-condition standards before automatic month-to-month or 12-month extensions trigger.
- Carrier and freight agreements often specify rate-table expiration dates or fuel surcharge adjustments.
- Flag minimum volume commitments or rebate clawback clauses.
""",
    },

    "general_b2b": {
        "display_name": "General Business",
        "route_path": "/",
        "default_alert_lead_days": 30,
        "headline": "Never Miss a B2B Contract Renewal or Silent SaaS Price Hike Again",
        "subheadline": "The AI-powered contract watchdog for growing businesses. Forward vendor renewal emails, invoices, and service agreements. Our AI extracts notice deadlines, calculates exact cancellation cutoffs, and alerts your team before evergreen renewals lock in.",
        "roi_hook": "The average B2B business saves $32,000 annually by stopping unused software subscriptions and auto-renewing vendor lock-ins.",
        "trust_strip": "Monitoring $48M+ in active vendor spend across 500+ fast-growing organizations.",
        "trust_badges": ["Google Gemini 3.5 AI", "Fernet Token Encryption", "SOC 2 Ready Architecture", "Postmark Direct Integration", "Zero Setup Required"],
        "cta_text": "Start Free Contract Review",
        "stat_metric": "$32,000",
        "stat_label": "Average Annual Spend Saved",
        "traps_highlighted": [
            {
                "title": "Automatic 12-Month Evergreen Lock-In",
                "desc": "Vendors converting monthly pilot plans into annual locked-in agreements when cancellation windows close unnoticed.",
            },
            {
                "title": "Silent Compounding Price Escalations",
                "desc": "Unchecked 5% to 10% automatic annual price increases hidden deep in standard terms of service and fine print.",
            },
            {
                "title": "Notice Window Miscalculations",
                "desc": "Confusing 30, 60, or 90 business-day notice requirements that trick teams into missing cancellation cutoffs.",
            },
        ],
        "categories": [
            "Software & SaaS",
            "Professional Services",
            "Office & Facilities",
            "Insurance & Compliance",
            "Marketing & Agencies",
            "Other Business Vendor",
        ],
        "search_keywords": [
            "renewal", "auto-renew", "subscription", "service agreement",
            "notice period", "cancellation", "price increase", "effective date"
        ],
        "llm_domain_hints": """
ACTIVE VERTICAL: General Business
ALLOWED CATEGORIES: ["Software & SaaS", "Professional Services", "Office & Facilities", "Insurance & Compliance", "Marketing & Agencies", "Other Business Vendor"]
INDUSTRY TRAPS TO PRIORITIZE:
- Focus on standard SaaS and B2B service auto-renewal cutoffs, conversions from monthly to annual lock-in, and renewal price increases (e.g., 5-10% uplift caps).
""",
    },
}

# Mapping from vertical route slug to vertical_id
VERTICAL_ROUTE_MAP = {
    "/property-management": "property_mgmt",
    "/dental-clinics": "dental_medical",
    "/msp": "msp_it",
    "/logistics": "logistics_mfg",
    "/": "general_b2b",
}

# Mapping from vertical_id to vertical route slug
VERTICAL_URL_PATHS = {
    "property_mgmt": "/property-management",
    "dental_medical": "/dental-clinics",
    "msp_it": "/msp",
    "logistics_mfg": "/logistics",
    "general_b2b": "/",
}
