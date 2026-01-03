import requests
import re

def extract_sender_domain(headers):
    match = re.search(r"From:.*?@([^\s>]+)", headers, re.IGNORECASE)
    if match:
        domain = match.group(1).strip().rstrip(';')
        return domain
    return None

def check_sender_domain(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        return {"error": f"VirusTotal request failed with status {response.status_code}"}

    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)
    categories = data.get("data", {}).get("attributes", {}).get("categories", {})

    return {
        "domain": domain,
        "reputation": reputation,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "categories": categories
    }
