# 🛡️ Serverless SOC Lab — AI-Powered Threat Detection & Response

> **Khóa luận tốt nghiệp** — Thử nghiệm Google Chronicle: Ứng dụng AI trong giám sát và phản ứng an ninh trên nền tảng Google Cloud.

## 📋 Tổng quan

Hệ thống **Serverless SOC** (Security Operations Center) là một pipeline **event-driven** hoàn toàn serverless trên Google Cloud Platform, kết hợp:

- 🤖 **AI-powered threat triage** — Gemini 2.5 Flash + OpenAI GPT fallback
- 🌍 **Context enrichment đa lớp** — IP Geolocation, User Agent, Time-of-Day
- 👤 **Human-in-the-loop remediation** — Phê duyệt qua Telegram Bot
- 🔐 **Defense-in-Depth** — HMAC-SHA256, link expiry, one-time-use guard

## 🏗️ Kiến trúc

```
Cloud Storage (Honeypot)
    → Cloud Audit Logs (Data Access)
    → Log Sink → Pub/Sub
    → Log-based Metric → Alert Policy (≥25 downloads/60s)
    → Pub/Sub → Orchestrator Bot (Cloud Function)
        → Context Enrichment (4 lớp)
        → AI Triage (Gemini + OpenAI fallback)
        → Telegram Alert (HMAC-SHA256 signed URL)
    → Webhook Remediation (Cloud Function)
        → IAM Disable Service Account
        → SCC V2 Finding (MITRE ATT&CK)
        → Cloud Logging audit trail
```

## 📁 Cấu trúc Dự án

```
├── main.tf                          # Root Terraform configuration
├── variables.tf                     # Input variables
├── outputs.tf                       # Output values
├── providers.tf                     # GCP provider config
├── backend.tf                       # Terraform state backend
├── terraform.tfvars.example         # Example variable values
├── .env.example                     # Example environment variables
│
├── modules/
│   ├── iam/                         # Service Accounts + IAM roles
│   ├── network/                     # VPC + Firewall rules
│   ├── storage/                     # Honeypot bucket
│   ├── logging_data/                # Log Sink + Pub/Sub routing
│   ├── monitoring/                  # Log-based Metric + Alert Policy
│   ├── scc/                         # Security Command Center source
│   └── serverless/                  # Cloud Functions (Gen2)
│
├── src/
│   ├── orchestrator_bot/            # AI triage + enrichment + alert
│   │   ├── main.py
│   │   └── requirements.txt
│   └── webhook_remediation/         # IAM disable + SCC Finding
│       ├── main.py
│       └── requirements.txt
│
└── attack_simulation.py             # Attack simulation script
```

## ⚡ Tính năng chính

### 1. Phát hiện Event-Driven
- **Honeypot Bucket** bẫy phát hiện truy cập trái phép
- **Log-based Metric** đếm `storage.objects.get` theo `principalEmail`
- **Alert Policy** kích hoạt khi vượt ngưỡng 25 downloads/60 giây

### 2. Context Enrichment (4 lớp)

| Lớp | Nguồn dữ liệu | Thông tin |
|---|---|---|
| Lớp 1: Cloud Logging Query | Cloud Logging API | `callerIp` + `userAgent` |
| Lớp 2: IP Geolocation | ip-api.com | Country, City, ISP |
| Lớp 3: User Agent Analysis | Phân tích chuỗi User Agent | Tool/client identification |
| Lớp 4: Time-of-Day | Python datetime (UTC+7) | Business hours, day of week |

### 3. AI Triage (Dual-AI)
- **Primary**: Gemini 2.5 Flash (temperature=0.1, timeout=30s)
- **Fallback**: OpenAI GPT (tự động chuyển khi Gemini lỗi)
- AI **tự reasoning** dựa trên enrichment signals — không code cứng severity

### 4. Human-in-the-Loop Remediation
- Cảnh báo qua **Telegram Bot** với inline button "Approve Remediation"
- URL phê duyệt được ký **HMAC-SHA256** (chống giả mạo)
- **Link expiry** (tối đa 1 giờ) + **One-time-use guard** (chống double-remediation)

### 5. Automated Response
- Vô hiệu hóa Service Account qua **IAM REST API**
- Tạo **SCC V2 Finding** với MITRE ATT&CK mapping
- Ghi **audit trail** vào Cloud Logging

## 🧪 Kết quả Test — Ma trận Đánh giá AI (12 kịch bản đại diện / 18 tổng)

| IP | User Agent | Thời gian | Severity | Confidence |
|---|---|---|---|---|
| 🇻🇳 Việt Nam | gsutil (CLI) | Giờ hành chính | **HIGH** | 0.90 |
| 🇻🇳 Việt Nam | Python SDK | Ngoài giờ | **HIGH** | 0.90 |
| 🇳🇱 Netherlands (VPN) | gsutil (CLI) | Giờ hành chính | **CRITICAL** | 1.00 |
| 🇸🇬 Singapore (VPN) | Python SDK | Giờ hành chính | **CRITICAL** | 0.90 |
| 🇳🇱 Netherlands (VPN) | Python SDK | Ngoài giờ | **CRITICAL** | 1.00 |
| 🇯🇵 Nhật Bản (VPN) | Python SDK | Cuối tuần | **CRITICAL** | 0.95 |

## 🚀 Triển khai

### Yêu cầu
- [Terraform](https://www.terraform.io/) ≥ 1.5
- [Google Cloud SDK](https://cloud.google.com/sdk)
- Python ≥ 3.11
- GCP Project với các API đã bật: Cloud Functions, Cloud Monitoring, Cloud Logging, Security Command Center, IAM

### Bước 1: Cấu hình biến

```bash
cp terraform.tfvars.example terraform.tfvars
# Chỉnh sửa terraform.tfvars với thông tin dự án GCP
```

### Bước 2: Triển khai hạ tầng

```bash
terraform init
terraform plan -out=tfplan
terraform apply "tfplan"
```

### Bước 3: Mô phỏng tấn công

```bash
# Trích xuất key của service account victim-employee từ terraform output
terraform output -raw victim_sa_json_key | Out-File -Encoding ASCII victim_key.json

# Cách 1: gsutil CLI
gcloud auth activate-service-account --key-file=victim_key.json
gsutil -m cp -r gs://<honeypot-bucket>/* .

# Cách 2: Python SDK (user agent khác biệt)
pip install google-cloud-storage
python attack_simulation.py
```

## 🔧 Biến môi trường

| Biến | Mô tả | Bắt buộc |
|---|---|---|
| `PROJECT_ID` | GCP Project ID | ✅ |
| `PROJECT_NUMBER` | GCP Project Number | ✅ |
| `GEMINI_API_KEY` | API Key cho Gemini | ✅ |
| `OPENAI_API_KEY` | API Key cho OpenAI (fallback) | ✅ |
| `TELE_BOT_TOKEN` | Telegram Bot Token | ✅ |
| `TELE_CHAT_ID` | Telegram Chat ID | ✅ |
| `WEBHOOK_BASE_URL` | URL của webhook Cloud Function | ✅ |
| `APPROVAL_SIGNING_SECRET` | Secret cho HMAC-SHA256 | ✅ |
| `SCC_SOURCE_NAME` | SCC source path | ✅ |

Xem `.env.example` để biết danh sách đầy đủ.

## 🔒 Bảo mật — Defense-in-Depth

| Lớp | Cơ chế | Mục đích |
|---|---|---|
| Phát hiện | Honeypot + Threshold Alert | Phát hiện truy cập bất thường |
| Phân tích | AI Triage + 4 lớp Enrichment | Đánh giá mức độ nghiêm trọng |
| Xác thực | HMAC-SHA256 + Link Expiry | Chống giả mạo approval URL |
| Idempotent | One-time-use Guard | Ngăn double-remediation |
| Phản ứng | Auto-disable SA + SCC Finding | Vô hiệu hóa mối đe dọa |
| Kiểm toán | Cloud Logging + SCC | Audit trail đầy đủ |

## 📦 Dependencies

### Orchestrator Bot
```
functions-framework==3.5.0
python-dotenv==1.0.1
requests==2.32.3
google-auth==2.38.0
```

### Webhook Remediation
```
functions-framework==3.5.0
python-dotenv==1.0.1
google-auth==2.38.0
google-cloud-securitycenter==2.7.0
```

### IAM Roles (`soar-orchestrator-sa`)
| Role | Mục đích |
|---|---|
| `roles/iam.serviceAccountAdmin` | Vô hiệu hóa SA bị xâm nhập |
| `roles/securitycenter.admin` | Tạo SCC Finding |
| `roles/logging.privateLogViewer` | Truy vấn Data Access audit logs |

## 📊 Hiệu năng

| Chỉ số | Giá trị |
|---|---|
| T_response trung bình | ~265 giây (~4.4 phút) |
| Độ lệch chuẩn (σ) | 17.8 giây |
| T_response nhanh nhất | 236 giây (kịch bản #11) |
| T_response chậm nhất | 292 giây (kịch bản #8) |
| Pipeline ứng dụng (enrichment + AI + Telegram) | ~12 giây (~4%) |
| Hạ tầng Cloud Monitoring | ~253 giây (~96%) |

## 📄 Giấy phép

Dự án này được phát triển cho mục đích nghiên cứu và học thuật (Khóa luận tốt nghiệp — ĐH Khoa học Tự nhiên TP.HCM).
