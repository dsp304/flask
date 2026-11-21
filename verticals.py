VERTICAL_CONFIGS = {
    "property_mgmt": {
        "display_name": "Property Management",
        "default_alert_lead_days": 45,
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
        "default_alert_lead_days": 60,
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
        "default_alert_lead_days": 30,
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
        "default_alert_lead_days": 45,
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
        "default_alert_lead_days": 30,
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
