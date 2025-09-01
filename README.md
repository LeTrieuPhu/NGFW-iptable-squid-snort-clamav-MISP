## Next Generation Firewall
Tường lửa thế hệ mới tích hợp các chức năng như Stateful firewall(iptable), Proxy(Squid), IDPS(Snort), AntiVirus(ClamAV) và phần mềm chia sẻ mối đe dọa(MISP)

# Sơ đồ mạng
![Sơ đồ mạng](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Tong%20quan.png)

# Functional Architecture
![Functional Architecture 1](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Functional%20Architecture%201.png)
![Functional Architecture 2](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Functional%20Architecture%202.png)

# Application-Data Architecture
![Application-Data Architecture](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Application-Data%20Architecture.png)

# Hướng dẫn cấu hình địa chỉ IP và iptable
1. **Cấu hình IP trên Ubuntu**
- Bước 1:
```bash
sudo nano /etc/netplan/00-installer-config.yaml
```
- Bước 2: Copy nội dụng vào file
```yaml
network:
  ethernets:
    ens33:
      dhcp4: no
      addresses: [192.168.60.1/24]  # Địa chỉ IP tĩnh bạn muốn
      gateway4: 192.168.60.254      # Gateway của mạng
    nameservers:
      addresses: [8.8.8.8, 8.8.4.4]  # DNS server
  version: 2
```
- Bước 3:
```bash
sudo netplan apply
```
- Bước 4: kiểm tra lại địa chỉ ip:
```bash
ip -a
```
2. **Cấu hình forward gói tin trên firewall**
- Cấu hình cứng: Sửa giá trị net.ipv4.ip_forward trong file /etc/sysctl.conf thành 1
```bash
sudo nano /etc/sysctl.conf
```
- Cấu hình động (sẽ khôi phục lại ban đầu nếu khởi động lại firewall):
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```
- Kiểm tra:
```bash
sudo sysctl -p
```
3. **Rule iptable**
- Rule chi tiết nằm trong file [SetupIPTABLES.txt](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/iptables/SetupIPTABLES.txt)

# Cài đặt và cấu hình Squid
1. **Cài đặt**
```bash
sudo apt install squid
```
2. **Kiểm tra**
```bash
squid --version
```
3. **Tạo danh sách Web được phép truy cập**
```bash
sudo nano /etc/squid/allowsites
```
4. **Thêm URL**
Ví Dụ:
```bash
student.uit.edu.vn
daa.uit.edu.vn
courses.uit.edu.vn
.youtube.com
.eicar.org
```
5. **Cấu hình Squid**
- Mở file cấu hình
```bash
sudo nano /etc/squid/squid.conf
```
- Tìm kiếm vị trí cấu hình
  - Nhấn tổ hợp phím **ctrl + W** để mở thành tìm kiếm
  - Nhập **'acl local'**
  - Enter
- Dán nội dụng bên dưới vào:
```bash
# allow site
acl allowsites dstdomain "/etc/squid/allowsites"
http_access allow allowsites
http_access deny all

# xac thuc dang nhap ldap
auth_param basic program /usr/lib/squid/basic_ldap_auth -b "dc=nt140,dc=local" -f "uid=%s" -h 192.168.100.40
auth_param basic children 5
auth_param basic realm Proxy Authentication
auth_param basic credentialsttl 2 hours

# Định nghĩa ACL cho người dùng đã xác thực
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
```
- khởi động lại Squid
```bash
sudo systemctl restart squid
```
ℹ️ **Lưu ý: 'dc=nt140,dc=local'** là domain được tạo bởi LDAP và **'192.168.100.40'** là địa chỉ IP của **Host** mà **LDAP được cài đặt lên đó**
# Cài đặt và cấu hình Snort
1. Cài đặt và Kiểm tra phiên bản
```bash
sudo apt-get install snort
snort --version
```
2. Kiểm tra daq list
```bash
sudo snort --daq-list
```
- Đảm bảo **nfq** đã được cài đặt
3. Xóa rule mặc định của Snort và tạo file rule mới
- Xóa rules mặc định
```bash
sudo rm -fr /etc/snort/rules/*
```
- tạo file NGFW.rules với tên file tùy ý
```bash
sudo touch /etc/snort/rules/NGFW.rules
```
4. Tạo và cấu hình file NGFW.conf
- Tạo file NGFW.conf
```bash
sudo touch /etc/snort/NGFW.conf
```
- Cấu hình file NGFW.conf
```bash
config daq: nfq
config daq_mode: inline
config policy_mode: inline
config daq_var: queue=0

preprocessor http_inspect: global iis_unicode_map unicode.map 1252
preprocessor http_inspect_server: server default profile all ports { 80 8080 8180 } oversize_dir_length 500

include /etc/snort/rules/NGFW.rules
```
ℹ️ **Lưu ý: 'queue=0'** hàng đợi này phải được định tuyến trong **rule của iptable**
5. Chạy snort Inline mode
```bash
sudo snort -Q -c /etc/snort/NGFW.conf
```
6. Rule snort
- Rule chi tiết nằm trong file [Rule_Snort.txt](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/snort/Rule_Snort.txt)
