"""South African GBV support resources.

Verify every number with the organisation before launch; they change.
"""

PROVINCES = [
    "Eastern Cape", "Free State", "Gauteng", "KwaZulu-Natal", "Limpopo",
    "Mpumalanga", "North West", "Northern Cape", "Western Cape",
]

HELPLINES = {
    "saps": {"name": "SAPS Emergency", "number": "10111", "note": "Police emergency, 24/7"},
    "emergency_mobile": {"name": "Emergency (any cellphone)", "number": "112", "note": "Works without airtime"},
    "gbvcc": {
        "name": "GBV Command Centre",
        "number": "0800 428 428",
        "note": "Toll-free from any cellphone, 24/7. Also USSD *120*7867# or SMS 'Help' to 31531",
    },
    "stop_gbv": {"name": "Stop Gender Violence Helpline", "number": "0800 150 150", "note": "Free, 24/7"},
    "childline": {"name": "Childline", "number": "116", "note": "Free, for children and worried adults"},
    "sadag_suicide": {"name": "SADAG Suicide Crisis Line", "number": "0800 567 567", "note": "Free, 24/7"},
    "lifeline": {"name": "Lifeline Counselling", "number": "0861 322 322", "note": "24/7 counselling"},
    "tears": {"name": "TEARS Foundation", "number": "*134*7355#", "note": "Free USSD, sexual abuse support"},
    "legal_aid": {"name": "Legal Aid South Africa", "number": "0800 110 110", "note": "Free legal help"},
}

PROTECTION_ORDER_STEPS = [
    "Go to your nearest Magistrate's Court. It is free and you don't need a lawyer.",
    "Ask the clerk for a protection order application under the Domestic Violence Act. "
    "They must help you fill it in.",
    "Describe what happened, with dates. Your Dudu journal can help you remember.",
    "A magistrate can grant an interim protection order the same day if you are in danger.",
    "The sheriff or police serve the order on the abuser. You get a return date for the final order.",
    "A suspended warrant of arrest comes with the order. If they break it, call the police "
    "and show the order.",
]

SAFETY_PLAN_DOCUMENTS = [
    "ID / passport", "Birth certificates (yours and children's)", "Bank card", "SASSA card",
    "Medication & clinic card", "Protection order copy", "Spare keys", "Some cash / airtime",
]

JOURNAL_TYPES = ["physical", "emotional", "sexual", "financial", "threats", "online", "other"]


def pick(*keys):
    return [HELPLINES[k] for k in keys]
