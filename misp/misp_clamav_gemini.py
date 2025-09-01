import os
import sys
import time
import json
import re
import requests
from datetime import datetime
import google.generativeai as genai
from iptables_misp import load_cache_from_csv, save_ioc_to_csv
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



# --- CẤU HÌNH ---
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
config_file = "config.ini"
if (not MISP_URL or not MISP_KEY) and os.path.exists(config_file):
    # Nếu chưa có cấu hình qua env, thử đọc file config.ini
    try:
        import configparser
        config = configparser.ConfigParser()
        config.read(config_file)
        if not MISP_URL:
            MISP_URL = config.get("MISP", "url", fallback=None)
        if not MISP_KEY:
            MISP_KEY = config.get("MISP", "key", fallback=None)
        GEMINI_API_KEY = config.get("GEMINI", "key", fallback=None)
        if GEMINI_API_KEY:
            GEMINI_API_KEY = GEMINI_API_KEY
    except Exception as e:
        print(f"Error reading config file: {e}", file=sys.stderr)

if not all([MISP_URL, MISP_KEY, GEMINI_API_KEY]):
    print("Missing environment variables: MISP_URL, MISP_KEY, GEMINI_API_KEY")
    sys.exit(1)

# Cấu hình Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-2.0-flash")		

HEADERS = {
    "Authorization": MISP_KEY,
    "Accept": "application/json",
    "Content-Type": "application/json"
}
MISP_API_URL = MISP_URL.rstrip("/") + "/events"
VERIFY_SSL = False

# --- THEO DÕI FILE LOG (tail -f) ---
def follow(file_path):
    with open(file_path, 'r') as thefile:
        thefile.seek(0, os.SEEK_END)
        while True:
            line = thefile.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line

def validate_date_format(date_str):
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
        return date_str
    except ValueError:
        return time.strftime("%Y-%m-%d")
    
# --- GỌI GEMINI VÀ TRÍCH XUẤT IOC ---
def extract_clamav_ioc_json(log_line):
    prompt = (
        "You are a cybersecurity assistant. Analyze the following ICAP antivirus log line and extract key fields related to malware detection.\n"
        "Return a JSON object with exactly these keys:\n"
        "- date: Detection date in the format YYYY-MM-DD (e.g., 2025-06-08). If the log does not include a year, assume the current year. Do not include the time.\n"
        "- ip_src: source IP address that made the request\n"
        "- url: the full URL that was accessed and scanned\n"
        "- action: what ClamAV or the ICAP server decided to do (e.g., 'blocked', 'passed')\n"
        "- virus_name: the name of the virus detected (e.g., 'Eicar-Test-Signature')\n"
        "- tag: always return ['malware-download'] as the default tag\n"
        "\nOnly return valid JSON. Do not explain.\n\n"
        f"Log: {log_line.strip()}"
    )

    response = model.generate_content(prompt)
    result_text = response.text.strip()

    try:
        return json.loads(result_text)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', result_text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(0))
            except:
                pass
        raise ValueError("Gemini returned non-JSON content")

# --- GỬI IOC LÊN MISP ---
def send_clamav_to_misp(ioc):
    virus_name = ioc.get("virus_name", "Unknown Malware")
    url = ioc.get("url", "")
    info = f"ClamAV Alert - {virus_name}"
    date_str = ioc.get("date") or time.strftime("%Y-%m-%d")

    def attr(attr_type, val, cat, ids=True, comment=None):
        d = {
            "type": attr_type,
            "category": cat,
            "to_ids": ids,
            "distribution": "0",
            "value": val
        }
        if comment:
            d["comment"] = comment
        return d

    attrs = []
    # IP and Port
    if "ip_src" in ioc:
        attrs.append(attr("ip-src", ioc["ip_src"], "Network activity"))

    # URL
    if url:
        attrs.append(attr("url", url, "Network activity")) 
    
    if virus_name and virus_name != "-":
        attrs.append(attr("malware-type", virus_name, "Payload delivery", comment="Detected by ClamAV"))
    
    if not attrs:
        raise ValueError("No IOCs to send")

    event = {
        "Event": {
            "info": info,
            "date": date_str,
            "distribution": "0",
            "threat_level_id": "1",
            "analysis": "0",
            "Attribute": attrs,
            "Tag": [
                {"name": t} for t in ioc.get("tag", [])
            ]
        }
    }

    # file deepcode ignore SSLVerificationBypass: <please specify a reason of ignoring this>
    resp = requests.post(MISP_API_URL, headers=HEADERS, json=event, verify=VERIFY_SSL)
    if resp.status_code >= 300:
        raise Exception(f"MISP error {resp.status_code}: {resp.text}")
    print(f"✔ MISP event created for rule: {virus_name}")

def process_icap_log(LOG_FILE, URL_FILE, url_cache):
    for log_line in follow(LOG_FILE):
        if "[Action: blocked]" not in log_line:
            continue
        
        try:
            ioc = extract_clamav_ioc_json(log_line)  # gọi hàm xử lý
            send_clamav_to_misp(ioc)
            save_ioc_to_csv(URL_FILE, ioc, url_cache)
            
        except Exception as e:
            print(f"[!] Error: {e}")

# --- MAIN LOOP ---
if __name__ == "__main__":

    LOG_FILE = "/var/log/c-icap/virus_scan.log"
    URL_FILE = "list_url.csv"
    url_cache = set()

    # cache để tránh trung lặp tốc độ cao
    url_cache = load_cache_from_csv("url", URL_FILE)
    
    if not os.path.exists(LOG_FILE):
        print(f"Log file not found: {LOG_FILE}")
        sys.exit(1)

    print(f"Monitoring {LOG_FILE}...")
    process_icap_log(LOG_FILE, URL_FILE, url_cache)

