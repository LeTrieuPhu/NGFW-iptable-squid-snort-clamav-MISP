import os
import sys
import time
import threading
from misp_snort_gemini import process_snort_log
from misp_clamav_gemini import process_icap_log
from iptables_misp import load_cache_from_csv

IP_FILE = "/home/firewall/Desktop/GITHUB_ATMNC/misp/list_ip.csv"
URL_FILE = "/home/firewall/Desktop/GITHUB_ATMNC/misp/list_url.csv"
ip_cache = set()
url_cache = set()

# cache để tránh trung lặp tốc độ cao
ip_cache = load_cache_from_csv("ip_src", IP_FILE)
url_cache = load_cache_from_csv("url", URL_FILE)

if __name__ == "__main__":
    SNORT_LOG_FILE = "/var/log/snort/alert"
    ICAP_LOG_FILE = "/var/log/c-icap/virus_scan.log"
    missing = []
    if not os.path.exists(SNORT_LOG_FILE):
        missing.append(SNORT_LOG_FILE)
    if not os.path.exists(ICAP_LOG_FILE):
        missing.append(ICAP_LOG_FILE)

    if missing:
        print(f"[!] Log file(s) not found: {', '.join(missing)}")
        sys.exit(1)

    print(f"Monitoring {SNORT_LOG_FILE} And {ICAP_LOG_FILE}...")
    
    snort_thread = threading.Thread(target=process_snort_log, args=(SNORT_LOG_FILE, IP_FILE , ip_cache, ), daemon=True)
    icap_thread = threading.Thread(target=process_icap_log, args=(ICAP_LOG_FILE, URL_FILE, url_cache, ), daemon=True)

    snort_thread.start()
    icap_thread.start()

    snort_thread.join()
    icap_thread.join()

    try:
        while True:
            time.sleep(1)  # Giữ cho main thread sống
    except KeyboardInterrupt:
        print("\n[+] Stopped by user.")
