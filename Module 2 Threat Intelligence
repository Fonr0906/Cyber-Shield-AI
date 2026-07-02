"""
modules/threat_intelligence.py
Module 2 - Threat Intelligence Dashboard
"""

import hashlib
import base64
import requests

from utils.config import config
from utils.validators import detect_indicator_type, clean_input, is_private_ip


def lookup_indicator(indicator: str) -> dict:
indicator = clean_input(indicator)
indicator_type = detect_indicator_type(indicator)

if indicator_type == "unknown":
return {
"error": "Could not recognize this as a URL, domain, IP, or file hash.",
"indicator": indicator,
}

private_note = ""

if indicator_type == "ip" and is_private_ip(indicator):
private_note = "This is a private/internal IP, so public threat feeds may not have data."

use_live = any(
config.has_key(key)
for key in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "URLSCAN_API_KEY"]
)

if use_live and not private_note:
result = _live_lookup(indicator, indicator_type)
else:
result = _demo_lookup(indicator, indicator_type)

if private_note:
result["explanation"] = private_note + " " + result.get("explanation", "")

return result


def _live_lookup(indicator: str, indicator_type: str) -> dict:
sources = []
malicious_reports = 0
location = "Unknown"
blacklisted = False

if config.has_key("VIRUSTOTAL_API_KEY"):
vt_result = _query_virustotal(indicator, indicator_type)

if vt_result:
sources.append(vt_result)
malicious_reports += vt_result.get("malicious", 0)
blacklisted = blacklisted or vt_result.get("malicious", 0) > 0

if indicator_type == "ip" and config.has_key("ABUSEIPDB_API_KEY"):
abuse_result = _query_abuseipdb(indicator)

if abuse_result:
sources.append(abuse_result)
malicious_reports += abuse_result.get("total_reports", 0)
location = abuse_result.get("country", location)
blacklisted = blacklisted or abuse_result.get("abuse_confidence", 0) >= 50

if indicator_type == "url" and config.has_key("URLSCAN_API_KEY"):
urlscan_result = _query_urlscan(indicator)

if urlscan_result:
sources.append(urlscan_result)
blacklisted = blacklisted or urlscan_result.get("malicious", False)

if not sources:
return _demo_lookup(
indicator,
indicator_type,
note="Live lookups failed or no API keys worked. Showing demo data.",
)

return _assemble_result(
indicator=indicator,
indicator_type=indicator_type,
sources=sources,
malicious_reports=malicious_reports,
location=location,
blacklisted=blacklisted,
demo=False,
)


def _query_virustotal(indicator: str, indicator_type: str):
base_url = "https://www.virustotal.com/api/v3"
headers = {
"x-apikey": config.VIRUSTOTAL_API_KEY
}

if indicator_type == "ip":
endpoint = f"{base_url}/ip_addresses/{indicator}"
elif indicator_type == "domain":
endpoint = f"{base_url}/domains/{indicator}"
elif indicator_type == "hash":
endpoint = f"{base_url}/files/{indicator}"
elif indicator_type == "url":
url_id = base64.urlsafe_b64encode(indicator.encode()).decode().strip("=")
endpoint = f"{base_url}/urls/{url_id}"
else:
return None

try:
response = requests.get(
endpoint,
headers=headers,
timeout=config.REQUEST_TIMEOUT,
)

if response.status_code != 200:
return None

data = response.json()

stats = (
data.get("data", {})
.get("attributes", {})
.get("last_analysis_stats", {})
)

malicious = stats.get("malicious", 0)
suspicious = stats.get("suspicious", 0)
harmless = stats.get("harmless", 0)

return {
"service": "VirusTotal",
"malicious": malicious,
"suspicious": suspicious,
"harmless": harmless,
"detail": f"{malicious} engines flagged this as malicious.",
}

except requests.RequestException:
return None


def _query_abuseipdb(ip_address: str):
try:
response = requests.get(
"https://api.abuseipdb.com/api/v2/check",
headers={
"Key": config.ABUSEIPDB_API_KEY,
"Accept": "application/json",
},
params={
"ipAddress": ip_address,
"maxAgeInDays": 90,
},
timeout=config.REQUEST_TIMEOUT,
)

if response.status_code != 200:
return None

data = response.json().get("data", {})

abuse_confidence = data.get("abuseConfidenceScore", 0)
total_reports = data.get("totalReports", 0)
country = data.get("countryCode", "Unknown")
isp = data.get("isp", "Unknown")

return {
"service": "AbuseIPDB",
"abuse_confidence": abuse_confidence,
"total_reports": total_reports,
"country": country,
"isp": isp,
"detail": f"Abuse confidence is {abuse_confidence}% from {total_reports} reports.",
}

except requests.RequestException:
return None


def _query_urlscan(url: str):
try:
response = requests.get(
"https://urlscan.io/api/v1/search/",
headers={
"API-Key": config.URLSCAN_API_KEY
},
params={
"q": f'page.url:"{url}"',
"size": 1,
},
timeout=config.REQUEST_TIMEOUT,
)

if response.status_code != 200:
return None

results = response.json().get("results", [])

malicious = False

if results:
malicious = bool(
results[0]
.get("verdicts", {})
.get("overall", {})
.get("malicious", False)
)

return {
"service": "URLScan.io",
"malicious": malicious,
"detail": "Recent scan flagged malicious."
if malicious
else "No malicious verdict in recent scans.",
}

except requests.RequestException:
return None


DEMO_BAD_INDICATORS = {
"malware-traffic.test",
"phishing-example.test",
"evil-login.test",
"192.0.2.66",
"203.0.113.99",
"44d88612fea8a8f36de82e1278abb02f",
}

DEMO_SUSPICIOUS_INDICATORS = {
"free-prize.top",
"verify-account.click",
"198.51.100.23",
}


def _demo_lookup(indicator: str, indicator_type: str, note: str = "") -> dict:
lowered_indicator = indicator.lower()

if lowered_indicator in DEMO_BAD_INDICATORS:
malicious_reports = 47
blacklisted = True
verdict_type = "bad"

elif lowered_indicator in DEMO_SUSPICIOUS_INDICATORS:
malicious_reports = 10
blacklisted = False
verdict_type = "suspicious"

else:
digest = int(hashlib.sha256(lowered_indicator.encode()).hexdigest(), 16)
bucket = digest % 100

if bucket < 12:
malicious_reports = 30 + bucket
blacklisted = True
verdict_type = "bad"
elif bucket < 30:
malicious_reports = 9 + (bucket % 4)
blacklisted = False
verdict_type = "suspicious"
else:
malicious_reports = 0
blacklisted = False
verdict_type = "clean"

location = "Unknown"

if indicator_type == "ip":
countries = ["US", "RU", "CN", "NL", "DE", "BR", "IN", "GB"]
country_index = int(hashlib.md5(lowered_indicator.encode()).hexdigest(), 16) % len(countries)
location = countries[country_index]

detail_map = {
"bad": f"{malicious_reports} demo engines flagged this indicator.",
"suspicious": f"{malicious_reports} demo engines raised low-confidence flags.",
"clean": "No demo engines flagged this indicator.",
}

sources = [
{
"service": "VirusTotal Demo",
"malicious": malicious_reports if verdict_type in ["bad", "suspicious"] else 0,
"detail": detail_map[verdict_type],
}
]

if indicator_type == "ip":
sources.append(
{
"service": "AbuseIPDB Demo",
"detail": f"Demo abuse confidence: {'high' if blacklisted else 'low'}; country: {location}.",
}
)

result = _assemble_result(
indicator=indicator,
indicator_type=indicator_type,
sources=sources,
malicious_reports=malicious_reports,
location=location,
blacklisted=blacklisted,
demo=True,
)

if note:
result["explanation"] = note + " " + result["explanation"]

return result


def _assemble_result(
indicator: str,
indicator_type: str,
sources: list,
malicious_reports: int,
location: str,
blacklisted: bool,
demo: bool,
) -> dict:
risk_score = min(malicious_reports * 4, 90)

if blacklisted:
risk_score = max(risk_score, 70)

risk_score = min(risk_score, 100)
reputation_score = 100 - risk_score

if risk_score >= 70:
verdict = "Malicious"
trust_advice = "Do NOT trust this. Avoid interacting with it and block it if possible."
elif risk_score >= 35:
verdict = "Suspicious"
trust_advice = "Treat this with caution. Verify it through another trusted source before using it."
else:
verdict = "Likely Safe"
trust_advice = "No significant threat signals were found, but still be cautious."

explanation = (
f"This {indicator_type} has a reputation score of {reputation_score}/100. "
f"{'It appears on a blacklist. ' if blacklisted else ''}"
f"{malicious_reports} malicious report(s) were found. "
f"{trust_advice}"
)

return {
"indicator": indicator,
"indicator_type": indicator_type,
"reputation_score": reputation_score,
"risk_score": risk_score,
"verdict": verdict,
"blacklisted": blacklisted,
"malicious_reports": malicious_reports,
"location": location,
"sources": sources,
"explanation": explanation,
"demo": demo,
}
