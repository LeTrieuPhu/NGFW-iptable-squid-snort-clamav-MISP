## Next Generation Firewall
Tường lửa thế hệ mới tích hợp các chức năng như Stateful firewall(iptable), Proxy(Squid), IDPS(Snort), AntiVirus(ClamAV) và phần mềm chia sẻ mối đe dọa(MISP)

# Sơ đồ mạng
![Sơ đồ mạng](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Tong%20quan.png)

# Functional Architecture
![Functional Architecture 1](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Functional%20Architecture%201.png)
![Functional Architecture 2](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Functional%20Architecture%202.png)

# Application-Data Architecture
![Application-Data Architecture](https://github.com/LeTrieuPhu/NGFW-iptable-squid-snort-clamav-MISP/blob/main/report/Application-Data%20Architecture.png)

# Hướng dẫn cấu hình
1. Cấu hình IP trên Ubuntu
    - Bước 1: sudo nano /etc/netplan/00-installer-config.yaml
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
  version: 2 \`\`\`
    - Bước 3: sudo netplan apply
    - Bước 4: kiểm tra lại địa chỉ ip: ip -a
2. 
