## Next Generation Firewall
Tường lửa thế hệ mới tích hợp các chức năng như Stateful firewall(iptable), Proxy(Squid), IDPS(Snort), AntiVirus(ClamAV) và phần mềm chia sẻ mối đe dọa(MISP)
## Mục Lục
- [Sơ đồ mạng](#Sơ-đồ-mạng)
- [Functional Architecture](#Functional-Architecture)
- [Application-Data Architecture](#Application-Data-Architecture)
- [Hướng dẫn cấu hình địa chỉ IP và iptable](#Hướng-dẫn-cấu-hình-địa-chỉ-IP-và-iptable)
- [Cài đặt và cấu hình Squid](#Cài-đặt-và-cấu-hình-Squid)
- [Cài đặt và cấu hình Snort](#Cài-đặt-và-cấu-hình-Snort)
- [Cài đặt và cấu hình ClamAV và CICAP](#Cài-đặt-và-cấu-hình-ClamAV-và-CICAP)
- [Cài đặt và sử dụng MISP](#Cài-đặt-và-sử-dụng-MISP)
- [Cài đặt và cấu hình DVWA](#Cài-đặt-và-cấu-hình-DVWA)
- [Cài đặt và Cấu hình LDAP Server và LDAP Client](#Cài-đặt-và-Cấu-hình-LDAP-Server-và-LDAP-Client)
# Sơ đồ mạng
![Sơ đồ mạng](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Tong%20quan.png)

# Functional Architecture
![Functional Architecture 1](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Functional%20Architecture%201.png)
![Functional Architecture 2](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Functional%20Architecture%202.png)

# Application-Data Architecture
![Application-Data Architecture](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Application-Data%20Architecture.png)

# Hướng dẫn cấu hình địa chỉ IP và iptable
>ℹ️ **Lưu ý:**
> Sử dụng Ubuntu 22.04 trở lên
> iptable, squid, snort, ClamAV, MISP được cấu hình trên cùng một máy firewall
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
>ℹ️ **Lưu ý: 'dc=nt140,dc=local'** là domain được tạo bởi LDAP và **'192.168.100.40'** là địa chỉ IP của **Host** mà **LDAP được cài đặt lên đó**
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
>ℹ️ **Lưu ý: 'queue=0'** hàng đợi này phải được định tuyến trong **rule của iptable**
5. Chạy snort Inline mode
```bash
sudo snort -Q -c /etc/snort/NGFW.conf
```
6. Rule snort
- Rule chi tiết nằm trong file [Rule_Snort.txt](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/snort/Rule_Snort.txt)
# Cài đặt và cấu hình ClamAV và CICAP
1. ClamAV
- Cài đặt
```bash
sudo apt install clamav clamav-daemon clamav-freshclam
```
- Sửa file /etc/clamav/clamd.conf
```bash
sudo nano /etc/clamav/clamd.conf
```
- command localsocket
```bash
# LocalSocket /run/clamav/clamd.sock
```
- Thêm IP(gateway mạng nội bộ), thêm port
```bash
TCPSocket 3310
TCPAddr 192.168.100.1
```
- Kiểm tra đã mở port chưa
```bash
sudo ss -tulnp | grep 3310
```
- Nếu đợi chưa thấy mở thì restart
```bash
sudo systemctl restart clamav-daemon
```
- Cập nhật chữ ký
```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
sudo systemctl enable --now clamav-freshclam
```
- khởi động cho nhận chữ ký và kiểm tra status
```bash
sudo systemctl restart clamav-daemon
sudo systemctl status clamav-daemon
```
> ℹ️ **Lưu ý:** Log của ClamAV
> ```bash
> sudo nano /var/log/clamav/clamav.log
> ```
2. CICAP
- Cài đặt
```bash
sudo apt install c-icap libicapapi-dev libc-icap-mod-virus-scan
```
- cấu hình /etc/c-icap/c-icap.conf
```bash
sudo nano /etc/c-icap/c-icap.conf

Cấu hình tương tự

Include /etc/c-icap/virus_scan.conf
PidFile /run/c-icap/c-icap.pid
CommandsSocket /run/c-icap/c-icap.ctl
Timeout 300
MaxKeepAliveRequests 100
KeepAliveTimeout 600
StartServers 3
MaxServers 10
ThreadsPerChild 10
Port 1344
User c-icap
Group c-icap
TmpDir /var/tmp
MaxMemObject 131072
DebugLevel 1
ModulesDir /usr/lib/x86_64-linux-gnu/c_icap
ServicesDir /usr/lib/x86_64-linux-gnu/c_icap
TemplateDir /usr/share/c_icap/templates/
TemplateDefaultLanguage en
LoadMagicFile /etc/c-icap/c-icap.magic
acl all src 0.0.0.0/0.0.0.0
acl PERMIT_REQUESTS type REQMOD RESPMOD
icap_access allow all PERMIT_REQUESTS
ServerLog /var/log/c-icap/server.log
AccessLog /var/log/c-icap/access.log
```
- Tắt các dịch vụ nội bộ không cần thiết (tuỳ chọn)
```bash
# Service url_check_module srv_url_check.so
```
> ℹ️ **Lưu ý:** thư mục **/usr/lib/x86_64-linux-gnu/c_icap**: xem đúng đường dẫn chưa và kiểm tra xem có virus_scan.so clamd_mod.so, nếu chưa phải tự tìm hiểu cài đặt. Còn mấy thư mục khác không quan trọng
- Chỉnh sửa hoặc tạo nếu chưa có file /etc/c-icap/virus_scan.conf
```bash
sudo nano /etc/c-icap/virus_scan.conf

Cấu hình tương tự

Service antivirus_module virus_scan.so
ServiceAlias srv_clamav virus_scan
ServiceAlias avscan virus_scan?allow204=on&sizelimit=off&mode=simple
virus_scan.ScanFileTypes TEXT DATA EXECUTABLE ARCHIVE
virus_scan.SendPercentData 5
virus_scan.StartSendPercentDataAfter 2M
virus_scan.MaxObjectSize 5M
virus_scan.DefaultEngine clamd
Include /etc/c-icap/clamd_mod.conf
```
> ℹ️ **Lưu ý:** **virus_scan** ở **"ServiceAlias srv_clamav virus_scan"** là module còn srv_clamav là dịch vụ mình sẽ gọi trong squid
- Sửa hoặc tạo nếu chưa có file /etc/c-icap/clamd_mod.conf
```bash
sudo nano /etc/c-icap/clamd_mod.conf

Cấu hình tương tự

Module common clamd_mod.so
clamd_mod.ClamdHost 192.168.100.1
clamd_mod.ClamdPort 3310
```
> ℹ️ **Lưu ý:** **IP** và **Port** phải trùng với ip và port được cấu hình ở **clamd**
- Khởi động và kiểm tra dịch vụ
```bash
sudo systemctl restart c-icap
sudo systemctl enable --now c-icap

sudo systemctl status c-icap
```
> ℹ️ **Lưu ý:** Log của CICAP
> ```bash
> /var/log/c-icap/server.log
> /var/log/c-icap/access.log
> ```
3. Tích hợp vào Squid
- Cấu hình trong /etc/squid/squid.conf
```bash
sudo nano /etc/squid/squid.conf
```
- Cấu hình tương tự, thường cấu hình ở cuối file
```bash
icap_enable on
icap_send_client_ip on
icap_preview_enable on
icap_preview_size 1024
icap_service avscan_req  reqmod_precache icap://192.168.100.1:1344/srv_clamav bypass=off
adaptation_access avscan_req allow all
icap_service avscan_resp respmod_precache icap://192.168.100.1:1344/srv_clamav bypass=off
adaptation_access avscan_resp allow all
```
> ℹ️ **Lưu ý: Thay đổi IP thành IP Gateway của mạng nội bộ** và dịch vụ sau port phải trùng với dịch vụ được cấu hình trong file **/etc/c-icap/virus_scan.conf**

# Cài đặt và sử dụng MISP
1. Cài đặt MISP
- Cài đặt
```bash
wget --no-cache -O /tmp/INSTALL.sh https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh ; bash /tmp/INSTALL.sh -c -M
```
- Truy cập Web: **IP của Host cài MISP**

>ℹ️ **Lưu ý:** 
>- User: admin@admin.test
>- Password: admin
>- Lưu lại **Authkey** của Admin, kết thúc phiên Key sẽ bị mã hóa
>- Nếu cài đặt không được, hãy thử đường dẫn này [install.sh](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/misp/install.sh)
# Cài đặt và cấu hình DVWA
1. Cập nhật hệ thống
```bash
sudo apt update && sudo apt upgrade -y
```
2. Cài Apache, PHP, MariaDB, Git
```bash
sudo apt install apache2 php php-mysqli php-gd libapache2-mod-php mariadb-server git -y
```
3. Khởi động dịch vụ
```bash
sudo systemctl enable apache2
sudo systemctl start apache2
sudo systemctl enable mariadb
sudo systemctl start mariadb
```
4. Tạo CSDL cho DVWA
```bash
sudo mysql -e "CREATE DATABASE dvwa;"
sudo mysql -e "CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'dvwa123';"
sudo mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"
```
5. Tải mã nguồn DVWA
```bash
cd /var/www/html
sudo git clone https://github.com/digininja/DVWA.git
```
6. Cấu hình DVWA
```bash
cd /var/www/html/DVWA/config
sudo cp config.inc.php.dist config.inc.php
sudo nano config.inc.php

# Chỉnh các dòng sau

$_DVWA[ 'db_user' ] = 'dvwa';
$_DVWA[ 'db_password' ] = 'dvwa123';
$_DVWA[ 'db_server' ] = '127.0.0.1';
```
7. Phân quyền
```bash
sudo chown -R www-data:www-data /var/www/html/DVWA
sudo chmod -R 755 /var/www/html/DVWA
```
8. Khởi động lại Apache
```bash
sudo systemctl restart apache2
```
9. Truy cập từ trình duyệt:
```bash
http://<ip_may_dvwa>/DVWA
```
10. Đăng nhập
```bash
Username: admin
Password: password
```
# Cài đặt và Cấu hình LDAP Server và LDAP Client
1. LDAP Server: [Video Hướng Dẫn](https://www.youtube.com/watch?v=yGJERaeZmKc) và [tài liệu tham khảo](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/ldap-squid-clamav/Setup_LDAP_Server.txt)
2. LDAP Client: [Video Hướng Dẫn](https://www.youtube.com/watch?v=WDdXcUG-Awk) và [tài liệu tham khảo](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/ldap-squid-clamav/Setup_LDAP_Client.txt)

# Hướng dẫn sử dụng và Khả năng chính của các công cụ
1. **iptable:** khả năng **Forward** và **NAT, Chặn IP, Ping, Telnet, SSH** đến server khi không được phép.
2. **Squid + LDAP:** Xác thực người dùng qua **tài khoản LDAP** và **giới hạn URL** có thể truy cập từ **người dùng nộ bộ**. Có thể kiếm tra bằng cách:
    - Truy cập 1 URL ngoài danh sách Allowsites: Kết quả mong đợi là **không thẻ truy cập web.**
    - Truy cập vào 1 URL trong danh sách Allowsites: Kết quả mong đợi là **yêu cầu đăng nhập** tài khoản và mật khẩu trước khi truy cập web. Nếu **đúng tài khoản và mật khẩu mới được phép truy cập.**
3. Squid + ClamAV: Khi tải file từ internet, Firewall sẽ **quét virus trên file này**. **Nếu an toàn**, file sẽ được tải về, ngược lại Firewall sẽ **cảnh báo dưới dạng html.**
4. Snort: **Phát hiện và ngăn chặn** các cuộc tấn công đến DVWA như: **SQL Injection, DoS hoặc Slowloris, Port Scan và Brute Force.** Cách kiểm tra được viết trong file [Rule_Snort.txt](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/snort/Rule_Snort.txt)
5.
