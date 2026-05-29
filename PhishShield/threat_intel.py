import requests
import time
import os
from dotenv import load_dotenv
#--------------VirusTotal API Access------------
load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
headers = {"x-apikey": API_KEY}
#-------------Normalize URL-------------------
def normalize_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url
#-------------getting output from VirusTotal----------------
def check_url_virustotal(url):
    url = normalize_url(url)
    vt_url = "https://www.virustotal.com/api/v3/urls"

    try:
        response = requests.post(vt_url,headers=headers,data={"url": url})
    except requests.exceptions.RequestException:
        return {"error": "Threat intelligence service unavailable."}
    if response.status_code != 200:
        return {"error": "Failed to submit URL to VirusTotal."}
    
    analysis_id = response.json()["data"]["id"]
    analysis_url = (f"https://www.virustotal.com/api/v3/analyses/{analysis_id}")
    stats = {}
    for _ in range(5):
        time.sleep(2)
        try:
            analysis_response = requests.get(analysis_url, headers=headers)
        except requests.exceptions.RequestException:
            return {"error": "Threat intelligence service unavailable."}
        if analysis_response.status_code != 200:
            continue
        stats = (analysis_response.json()["data"]["attributes"]["stats"])
        total = (
            stats.get("malicious", 0)
            + stats.get("suspicious", 0)
            + stats.get("harmless", 0)
            + stats.get("undetected", 0))
        if total > 0:
            break

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0)
    }
#-------------formatting VirusTootal output------------------
def format_vt_report(vt_result):
    if "error" in vt_result:
        return vt_result["error"]
    
    malicious = vt_result.get("malicious", 0)
    suspicious = vt_result.get("suspicious", 0)
    harmless = vt_result.get("harmless", 0)
    undetected = vt_result.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    if total == 0:
        return ("No threat intelligence data available for this URL.")

    return (
        f"Out of {total} security vendors, "
        f"{malicious} flagged it as malicious, "
        f"{suspicious} marked it suspicious, "
        f"and {harmless} considered it safe.")