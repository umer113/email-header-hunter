import requests
import base64
import time
import re

def extract_urls_from_body(body):
    return re.findall(r'https?://[^\s"\']+', body)


def scan_and_check_url(url, api_key):
    headers = {"x-apikey": api_key}

    scan_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        data={"url": url},
        headers={**headers, "Content-Type": "application/x-www-form-urlencoded"}
    )
    
    if scan_response.status_code != 200:
        return {}

    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    time.sleep(5)

    report_response = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{encoded_url}",
        headers=headers
    )
    
    data = report_response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return stats

url = "https://www.supportosumup.it/"
api_key = "c4ae9bec7a33813cb68fe89a1d214d794185a9e80536d958dd29e3ae345c79c0"
# print(scan_and_check_url(url, api_key))
