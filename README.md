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
- Rule chi tiết nằm trong file **/iptable/SetupIPTABLES.txt**

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
6. 
