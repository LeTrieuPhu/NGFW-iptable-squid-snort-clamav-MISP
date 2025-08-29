import os
import csv
import subprocess


IP_FILE = "list_ip.csv"
URL_FILE = "list_url.csv"
SQUID_BLACKLIST_FILE = "/etc/squid/blacklist"


ip_cache = set()
url_cache = set()


def load_cache_from_csv(field_name, filename):
    cache = set()
    if not os.path.isfile(filename):
        return cache
    with open(filename, mode="r", newline="") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            val = row.get(field_name)
            if val:
                cache.add(val)
    return cache


def block_ip_with_iptables(ip):
    try:
        subprocess.run(["sudo", "iptables", "-C", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
        print(f"[!] IP đã bị chặn trước đó : {ip}")
    except subprocess.CalledProcessError:
        subprocess.run(["sudo", "iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"], check=True)
        print(f"✅ Đã chặn IP bằng iptables: {ip}")

def add_url_to_squid_blacklist(url):
    try:
        with open(SQUID_BLACKLIST_FILE, "a") as f:
            f.write(url + "\n")
        print(f"✅ Đã thêm URL vào blacklist Squid: {url}")

        # Reload cấu hình Squid để áp dụng thay đổi
        subprocess.run(["sudo", "squid", "-k", "reconfigure"], check=True)
    
    except Exception as e:
        print(f"[!] Lỗi khi thêm URL vào blacklist: {e}")


def save_ioc_to_csv(filename, ioc, ioc_cache):
    # kiểm tra ioc có tồn tại không
    if not ioc:
        print(f"not ioc")
        return
    
    # Kiểm tra file là url hay ip dựa vào tên
    is_url_file = "url" in filename.lower()

    if is_url_file:
        fields = ["url"]
        value = ioc.get("url", "")

        if not value or value in ioc_cache:
            return
        
        ioc_cache.add(value)
        row = {"url": ioc.get("url", "")}
        add_url_to_squid_blacklist(value)
        
    else:
        fields = ["ip_src"]
        value = ioc.get("ip_src", "")

        if not value or value in ioc_cache:
            return
        
        ioc_cache.add(value)
        row = {"ip_src": ioc.get("ip_src", "")}
        block_ip_with_iptables(value)

    # Kiểm tra nếu file chưa tồn tại thì ghi header
    file_exists = os.path.isfile(filename)
    
    with open(filename, "a", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields)

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)
        print(f"lưu thành công ip vào {filename}")



if __name__ == "__main__":
    
    IP_FILE = "list_ip.csv"
    URL_FILE = "list_url.csv"
    SQUID_BLACKLIST_FILE = "/etc/squid/blacklist"


    ip_cache = set()
    url_cache = set()

    # cache để tránh trung lặp tốc độ cao
    ip_cache = load_cache_from_csv("ip_src", IP_FILE)
    url_cache = load_cache_from_csv("url", URL_FILE)

    ioc = {"ip_src": "192.168.1.10"}
    save_ioc_to_csv(IP_FILE, ioc, ip_cache)
