"""
modules/phone_intelligence.py
Module 4 - Phone Intelligence Lookup
"""

import hashlib
import requests

from utils.config import config
from utils.validators import clean_input, is_valid_phone

try:
import phonenumbers
from phonenumbers import carrier, geocoder, timezone as pn_timezone

HAS_PHONENUMBERS = True
except ImportError:
HAS_PHONENUMBERS = False


DEMO_SCAM_NUMBERS = {
"+18005551234",
"+19005550000",
"+14085550199",
}

DEMO_SPAM_NUMBERS = {
"+18885550100",
"+441234567890",
}


SCAM_CATEGORIES = [
"Robocall / Auto-dialer",
"Tech-support scam",
"IRS / tax scam",
"Bank impersonation",
"Package delivery scam",
"Prize / lottery scam",
"Debt collection scam",
]


def lookup_phone(raw_number: str, default_region: str = "US") -> dict:
number = clean_input(raw_number)

if not number:
return {"error": "Please enter a phone number."}

if not is_valid_phone(number):
return {"error": "That does not look like a valid phone number."}

parsed_info = _parse_number(number, default_region)

if parsed_info.get("error"):
return parsed_info

e164_number = parsed_info["e164"]
reputation = _assess_reputation(e164_number, parsed_info)

parsed_info.update(reputation)

return parsed_info


def _parse_number(number: str, default_region: str) -> dict:
if not HAS_PHONENUMBERS:
return {
"input": number,
"e164": number if number.startswith("+") else "+" + number.lstrip("+"),
"international": number,
"valid": True,
"carrier": "Unknown. Install phonenumbers for carrier details.",
"location": "Unknown",
"timezones": [],
"line_type": "Unknown",
}

try:
parsed_number = phonenumbers.parse(number, default_region)

except phonenumbers.NumberParseException as error:
return {
"error": f"Could not parse this number: {error}"
}

if not phonenumbers.is_valid_number(parsed_number):
return {
"error": "The number failed validation. It may have the wrong length or format."
}

number_type = phonenumbers.number_type(parsed_number)

type_map = {
phonenumbers.PhoneNumberType.MOBILE: "Mobile",
phonenumbers.PhoneNumberType.FIXED_LINE: "Landline",
phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed line or mobile",
phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-free",
phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium rate",
phonenumbers.PhoneNumberType.VOIP: "VoIP",
}

return {
"input": number,
"e164": phonenumbers.format_number(
parsed_number,
phonenumbers.PhoneNumberFormat.E164,
),
"international": phonenumbers.format_number(
parsed_number,
phonenumbers.PhoneNumberFormat.INTERNATIONAL,
),
"valid": True,
"carrier": carrier.name_for_number(parsed_number, "en") or "Unknown",
"location": geocoder.description_for_number(parsed_number, "en") or "Unknown",
"timezones": list(pn_timezone.time_zones_for_number(parsed_number)),
"line_type": type_map.get(number_type, "Unknown"),
}


def _assess_reputation(e164_number: str, info: dict) -> dict:
if config.has_key("NUMVERIFY_API_KEY"):
_numverify_enrich(e164_number, info)

score = 85
reasons = []
category = None

lowered_number = e164_number.lower()
line_type = info.get("line_type", "")

if lowered_number in DEMO_SCAM_NUMBERS:
score = 8
category = "Tech-support scam"
reasons.append("Number appears on a known scam list using demo data.")

elif lowered_number in DEMO_SPAM_NUMBERS:
score = 30
category = "Robocall / Auto-dialer"
reasons.append("Number appears on a known spam list using demo data.")

else:
digest = int(hashlib.sha256(lowered_number.encode()).hexdigest(), 16)
bucket = digest % 100

if line_type == "Premium rate":
score -= 45
category = "Prize / lottery scam"
reasons.append("Premium-rate numbers are often used in scams.")

if line_type == "VoIP":
score -= 20
reasons.append("VoIP numbers are cheap and commonly used for spam or scams.")

if line_type == "Toll-free":
score -= 5
reasons.append("Toll-free numbers are often used by mass callers.")

if bucket < 10:
score -= 40
category = category or SCAM_CATEGORIES[digest % len(SCAM_CATEGORIES)]
reasons.append("Demo community reports associate this pattern with scams.")

elif bucket < 25:
score -= 20
reasons.append("Some demo community spam reports exist for this pattern.")

score = max(0, min(score, 100))

if score < 25:
status = "Likely Scam"
advice = "Block and report this number. Do not answer or call back."

elif score < 50:
status = "Likely Spam"
advice = "Avoid answering. Consider blocking it and verify before trusting."

elif score < 75:
status = "Unverified"
advice = "Answer with caution or let it go to voicemail. Verify the caller."

else:
status = "Likely Legitimate"
advice = "No strong risk signals were found, but never share sensitive information on unexpected calls."

if not reasons:
reasons.append("No spam or scam reports were found for this number.")

return {
"trust_score": score,
"status": status,
"scam_category": category or "None identified",
"advice": advice,
"reasons": reasons,
"demo": not config.has_key("NUMVERIFY_API_KEY"),
}


def _numverify_enrich(e164_number: str, info: dict):
try:
response = requests.get(
"http://apilayer.net/api/validate",
params={
"access_key": config.NUMVERIFY_API_KEY,
"number": e164_number,
"format": 1,
},
timeout=config.REQUEST_TIMEOUT,
)

if response.status_code != 200:
return

data = response.json()

if data.get("valid"):
info["carrier"] = data.get("carrier") or info.get("carrier")
info["location"] = data.get("location") or info.get("location")
info["line_type"] = (
data.get("line_type") or info.get("line_type")
).title()

except requests.RequestException:
pass
