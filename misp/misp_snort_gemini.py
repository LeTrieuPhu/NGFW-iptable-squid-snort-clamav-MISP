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
def extract_snort_ioc_json(log_line):
    prompt = (
        "You are a cybersecurity assistant. Extract all relevant indicators of compromise (IOCs) "
        "and rule information from the following Snort/Suricata log line.\n"
        "Return a JSON object with these keys:\n"
        "- date: Detection date in the format YYYY-MM-DD (e.g., 2025-06-08). If the log does not include a year, assume the current year. Do not include the time.\n"
        "- ip_src: source IP\n"
        "- ip_dst: destination IP\n"
        "- port_src: source port\n"
        "- port_dst: destination port\n"
        "- domain: domain name\n"
        "- url: URL\n"
        "- rule_name: name or message of the rule (msg)\n"
        "- protocol: protocol (TCP, UDP, ...)\n"
        "- tag: an array of relevant threat tags (e.g., ['sql-injection', 'brute-force', 'port-scan', 'dos']) inferred from rule_name\n"
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
def send_snort_to_misp(ioc):
    rule_name = ioc.get("rule_name") or ioc.get("msg")
    info = f"Snort Alert - {rule_name}"
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
    if "port_src" in ioc:
        attrs.append(attr("port", ioc["port_src"], "Network activity", comment="Source port"))

    if "ip_dst" in ioc:
        attrs.append(attr("ip-dst", ioc["ip_dst"], "Network activity"))
    if "port_dst" in ioc:
        attrs.append(attr("port", ioc["port_dst"], "Network activity", comment="Destination port"))

    # Protocol (nếu có)
    if "protocol" in ioc:
        attrs.append(attr("text", ioc["protocol"], "Network activity", False, "Protocol used"))
    
    if not attrs:
        raise ValueError("No IOCs to send")

    event = {
        "Event": {
            "info": info,
            "date": date_str,
            "distribution": "0",
            "threat_level_id": "2",
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
    print(f"✔ MISP event created for rule: {rule_name}")


def process_snort_log(LOG_FILE, IP_FILE, ip_cache):
    
    log_buffer = []
    for log_line in follow(LOG_FILE):
        if '[**]' in log_line:
            log_buffer.clear()
        log_buffer.append(log_line.strip())
        
        # Nếu đã thu thập đủ 6 dòng
        if len(log_buffer) == 6:
            combined_log = '\n'.join(log_buffer)  # gộp lại thành 1 chuỗi
            try:
                ioc = extract_snort_ioc_json(combined_log)  # gọi hàm xử lý
                
                send_snort_to_misp(ioc)
                #kiểm tra tag, nếu thuộc dos thì không lưu ip
                tags = ioc.get("tag", [])
                if "dos" not in [t.lower() for t in tags]:
                    save_ioc_to_csv(IP_FILE, ioc, ip_cache)
                             
            except Exception as e:
                print(f"[!] Error: {e}")
            log_buffer.clear()
            
# --- MAIN LOOP ---
if __name__ == "__main__":
    
    LOG_FILE = "/var/log/snort/alert"
    IP_FILE = "list_ip.csv"
    ip_cache = set()

    # cache để tránh trung lặp tốc độ cao
    ip_cache = load_cache_from_csv("ip_src", IP_FILE)
    if not os.path.exists(LOG_FILE):
        print(f"Log file not found: {LOG_FILE}")
        sys.exit(1)

    print(f"Monitoring {LOG_FILE}...")
    process_snort_log(LOG_FILE, IP_FILE, ip_cache)

    
    
