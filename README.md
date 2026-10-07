# 🛡️ Home SOC Lab — Phát hiện & Điều tra tấn công SSH Brute-Force với Wazuh SIEM

> Dự án tự xây dựng một **Mini SOC (Security Operations Center)** trên môi trường ảo hóa, mô phỏng trọn vẹn một cuộc tấn công SSH brute-force từ góc nhìn kẻ tấn công, sau đó **phát hiện – điều tra – ứng phó** từ góc nhìn của một SOC Analyst.

---

## 📌 Tổng quan

| | |
|---|---|
| **Mục tiêu** | Dựng SIEM, tái hiện tấn công thật, thực hành quy trình Detection → Investigation → Response |
| **SIEM** | Wazuh 4.9.2 (all-in-one: Manager + Indexer + Dashboard) |
| **Kỹ thuật tấn công** | SSH Brute-Force (MITRE ATT&CK **T1110**) → Valid Accounts (**T1078**) |
| **Kết quả** | Phát hiện thành công chuỗi tấn công, xác định attacker, dựng lại dòng thời gian, đề xuất ứng phó |

---

## 🗺️ Mô hình Lab

```
┌──────────────────┐        SSH Brute-Force         ┌──────────────────────┐
│   Attacker (Kali)│  ───────(Hydra)────────────▶   │  Victim              │
│  192.168.91.129  │                                │  Metasploitable2     │
└──────────────────┘                                │  192.168.91.141      │
                                                     └───────────┬──────────┘
                                                                 │ syslog (UDP/514)
                                                                 ▼
                                                     ┌──────────────────────┐
                                                     │  Wazuh SIEM          │
                                                     │  192.168.91.140      │
                                                     │  Detection & Analysis│
                                                     └──────────────────────┘
```

| Vai trò | Máy | IP |
|---|---|---|
| Attacker | Kali Linux | `192.168.91.129` |
| Victim | Metasploitable2 | `192.168.91.141` |
| SIEM | Ubuntu + Wazuh | `192.168.91.140` |

> 📷 *Ảnh 1 — Dashboard Wazuh sau khi cài đặt thành công.*
> `![Wazuh Dashboard](images/01-wazuh-dashboard.png)`

---

## ⚙️ Các bước triển khai

### 1. Dựng Wazuh SIEM
Cài đặt all-in-one trên Ubuntu Server:
```bash
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
Truy cập dashboard qua `https://192.168.91.140` với tài khoản `admin`.

### 2. Thu thập log từ Victim (Agentless – Syslog)
Metasploitable2 quá cũ để cài Wazuh Agent, nên log được đẩy về SIEM qua **syslog**.

Trên **Victim** — `/etc/syslog.conf`:
```
*.*     @192.168.91.140
```
```bash
sudo /etc/init.d/sysklogd restart
```

Trên **Wazuh** — khai báo nhận syslog trong `/var/ossec/etc/ossec.conf`:
```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>192.168.91.0/24</allowed-ips>
</remote>
```
```bash
sudo systemctl restart wazuh-manager
```

Kiểm chứng luồng log bằng `tcpdump`:
```bash
sudo tcpdump -i any -n udp port 514
# IP 192.168.91.141.514 > 192.168.91.140.514: SYSLOG  ✅
```

> 📷 *Ảnh 2 — Dashboard Threat Hunting hiển thị Authentication Failure & phân loại Brute Force (MITRE ATT&CK).*
> `![Threat Hunting](02-threat-hunting.png.jpg)`

### 3. Tái hiện tấn công (Attacker – Kali)
```bash
# Thuật toán SSH cũ của Metasploitable cần được bật lại trong ssh_config
hydra -l msfadmin -P pass.txt ssh://192.168.91.141 -t 4 -V
```
Kết quả:
```
[22][ssh] host: 192.168.91.141   login: msfadmin   password: msfadmin
1 of 1 target successfully completed, 1 valid password found
```
→ Attacker **brute-force thành công** và chiếm được tài khoản.

> 📷 *Ảnh 3 — Hydra brute-force thành công, tìm ra mật khẩu.*
> `![Hydra Attack](03-hydra.png.jpg)`

---

## 🔍 Điều tra (Investigation)

### Phát hiện trên SIEM
Sau cuộc tấn công, dashboard ghi nhận: nhiều **Authentication failure** liên tiếp trong cùng một thời điểm (dấu hiệu của tool tự động), tiếp theo là **Authentication success** — mẫu hành vi điển hình của brute-force thành công.

> 📷 *Ảnh 4 — Số liệu alert tăng vọt & biểu đồ MITRE ATT&CK (Brute Force → Valid Accounts).*
> `![Alerts](04-alerts.png.jpg)`

### Bằng chứng (log gốc)
```
sshd[5481]: pam_unix(sshd:auth): authentication failure;
logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.91.129 user=msfadmin
```

| Trường | Giá trị |
|---|---|
| Rule ID | **2501** — User authentication failure |
| Rule level | 5 |
| Rule fired times | 4 |
| Rule groups | `authentication_failed` |
| Source IP (attacker) | `192.168.91.129` |
| Target user | `msfadmin` |
| Compliance mapping | PCI-DSS 10.2.4/10.2.5 · NIST 800-53 AU.14/AC.7 · HIPAA 164.312.b |

> 📷 *Ảnh 5 — Document Details: full_log, source IP, rule và mapping tuân thủ.*
> `![Event Detail](05-event-detail.png.jpg)`

### Bộ câu hỏi điều tra (SOC checklist)

| Câu hỏi | Kết luận |
|---|---|
| IP tấn công? | `192.168.91.129` (Kali) |
| Mục tiêu? | Host `192.168.91.141`, user `msfadmin` |
| Thời điểm? | 00:07:52 — 08/10/2026 |
| Số lần thất bại? | Nhiều lần liên tiếp (rule 2501 kích hoạt ≥4) |
| Có đăng nhập thành công không? | **Có** — attacker chiếm được tài khoản |
| Kỹ thuật (MITRE ATT&CK)? | T1110 Brute Force → T1078 Valid Accounts |

---

## 🚨 Ứng phó & Khuyến nghị (Response)

1. **Chặn ngay** IP nguồn `192.168.91.129` tại firewall.
2. **Đổi mật khẩu** tài khoản `msfadmin` và rà soát các tài khoản yếu.
3. Triển khai **fail2ban** / giới hạn số lần đăng nhập sai trên SSH.
4. **Vô hiệu hóa đăng nhập bằng mật khẩu**, chuyển sang xác thực bằng SSH key.
5. Tạo **rule cảnh báo chủ động** trên Wazuh khi phát hiện nhiều lần đăng nhập thất bại từ cùng một IP trong thời gian ngắn.

---

## 🧰 Công nghệ sử dụng
`Wazuh SIEM` · `Ubuntu Server` · `Kali Linux` · `Metasploitable2` · `THC-Hydra` · `Syslog` · `VMware Workstation` · `MITRE ATT&CK`

---

## 🎓 Kỹ năng thể hiện
- Triển khai và vận hành nền tảng SIEM (Wazuh)
- Cấu hình thu thập log tập trung (agentless / syslog)
- Mô phỏng tấn công & tư duy của attacker (Hydra, SSH)
- Phát hiện, điều tra và phân tích sự cố theo quy trình SOC
- Ánh xạ sự cố theo MITRE ATT&CK và các chuẩn tuân thủ (PCI-DSS, NIST, HIPAA)
- Viết báo cáo sự cố và đề xuất biện pháp ứng phó
