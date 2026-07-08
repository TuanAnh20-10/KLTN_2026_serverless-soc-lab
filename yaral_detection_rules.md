# YARA-L Detection Rules & BigQuery SQL Translation

> **Đề tài:** Thử nghiệm Google Chronicle — Ứng dụng AI trong giám sát và phản ứng an ninh trên nền tảng Google Cloud  
> **Dataset:** `linen-flash-490013-u3.soc_audit_dataset`  
> **Mục đích:** Viết luật YARA-L theo cú pháp Chronicle, sau đó chuyển đổi logic sang SQL để chạy trên BigQuery (do giới hạn license Chronicle)

---

## Mục lục

1. [Bảng ánh xạ trường UDM ↔ Cloud Audit Log](#1-bảng-ánh-xạ-trường-udm--cloud-audit-log)
2. [Luật 1: Mass Download Detection](#2-luật-1-mass-download-detection)
3. [Luật 2: Off-Hours Access Detection](#3-luật-2-off-hours-access-detection)
4. [Luật 3: Suspicious Tool Access Detection](#4-luật-3-suspicious-tool-access-detection)
5. [So sánh YARA-L vs SQL vs Alert Policy](#5-so-sánh-yara-l-vs-sql-vs-alert-policy)
6. [Hạn chế của phương pháp chuyển đổi](#6-hạn-chế-của-phương-pháp-chuyển-đổi)

---

## 1. Bảng ánh xạ trường UDM ↔ Cloud Audit Log

| Trường UDM (YARA-L) | Trường Cloud Audit Log (BigQuery) | Mô tả |
|---|---|---|
| `metadata.event_type` | *(giá trị UDM do parser suy luận)* | Loại hành vi đã chuẩn hóa (VD: `USER_RESOURCE_ACCESS`) |
| `metadata.product_event_type` | `protopayload_auditlog.methodName` | Phương thức gốc (VD: `storage.objects.get`) |
| `metadata.event_timestamp` | `timestamp` | Thời điểm sự kiện xảy ra |
| `principal.user.userid` | `protopayload_auditlog.authenticationInfo.principalEmail` | Tài khoản thực hiện hành vi |
| `principal.ip` | `protopayload_auditlog.requestMetadata.callerIp` | Địa chỉ IP nguồn |
| `network.http.user_agent` | `protopayload_auditlog.requestMetadata.callerSuppliedUserAgent` | Chuỗi User Agent |
| `target.resource.name` | `protopayload_auditlog.resourceName` | Tên tài nguyên bị truy cập |
| `target.resource.resource_type` | `resource.type` | Loại tài nguyên (UDM: `STORAGE_BUCKET`, raw: `gcs_bucket`) |

**Lưu ý:** Trong Chronicle, quá trình ánh xạ được thực hiện tự động bởi Parser. Trong đề tài, việc ánh xạ thủ công giúp hiểu sâu hơn về cấu trúc dữ liệu bên dưới lớp trừu tượng UDM.

---

## 2. Luật 1: Mass Download Detection

**Mô tả:** Phát hiện hành vi tải xuống số lượng lớn file từ Cloud Storage trong 1 phút.  
**MITRE ATT&CK:** T1020 — Automated Exfiltration  
**Severity:** HIGH  
**Tương đương:** Log-based Metric + Alert Policy đã triển khai (Mục 3.4.1 trong báo cáo)

### YARA-L Rule

```yara
rule gcs_mass_download_detection {
  meta:
    author = "SOC Lab - KLTN 2026"
    description = "Phát hiện tải xuống hàng loạt từ Cloud Storage trong 1 phút"
    severity = "HIGH"
    mitre_attack = "T1020 - Automated Exfiltration"

  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.metadata.product_event_type = "storage.objects.get"
    $e.principal.user.userid = $user
    $e.target.resource.resource_type = "STORAGE_BUCKET"

  match:
    $user over 1m

  outcome:
    $download_count = count($e.metadata.id)

  condition:
    $e and $download_count > 25
}
```

### BigQuery SQL

```sql
-- Luật 1: Mass Download Detection
-- Ngưỡng: > 25 lượt tải trong 1 phút (60 giây)
-- Tương đương: Alert Policy alignment_period = 60s, threshold = 25
-- Lưu ý: SQL chỉ tạo được tumbling window (không chồng lấn),
-- không hoàn toàn tương đương hop window (chồng lấn) của YARA-L
SELECT
  principal,
  minute_window,
  download_count
FROM (
  SELECT
    protopayload_auditlog.authenticationInfo.principalEmail AS principal,
    TIMESTAMP_TRUNC(timestamp, MINUTE) AS minute_window,
    COUNT(*) AS download_count
  FROM
    `linen-flash-490013-u3.soc_audit_dataset.cloudaudit_googleapis_com_data_access_*`
  WHERE
    protopayload_auditlog.methodName = 'storage.objects.get'
  GROUP BY principal, minute_window
)
WHERE download_count > 25
ORDER BY download_count DESC;
```

### Giải thích chuyển đổi

| Thành phần YARA-L | SQL tương ứng | Ghi chú |
|---|---|---|
| `events` filter | `WHERE methodName = 'storage.objects.get'` | Lọc sự kiện tải file |
| `$user` binding | `GROUP BY principal` | Nhóm theo tài khoản |
| `match $user over 1m` | `TIMESTAMP_TRUNC(timestamp, MINUTE)` | Hop window → Tumbling window |
| `count($e.metadata.id)` | `COUNT(*)` | Đếm số lượt tải |
| `$download_count > 25` | `WHERE download_count > 25` | Ngưỡng kích hoạt |

---

## 3. Luật 2: Off-Hours Access Detection

**Mô tả:** Phát hiện truy cập Cloud Storage ngoài giờ hành chính (trước 8:00 hoặc sau 18:00 UTC+7).  
**MITRE ATT&CK:** T1530 — Data from Cloud Storage  
**Severity:** MEDIUM  
**Tương đương:** Context Enrichment Layer 4 — Time-of-Day (Mục 3.4.2)

### YARA-L Rule

```yara
rule gcs_off_hours_access {
  meta:
    author = "SOC Lab - KLTN 2026"
    description = "Phát hiện truy cập Cloud Storage ngoài giờ hành chính (UTC+7)"
    severity = "MEDIUM"
    mitre_attack = "T1530 - Data from Cloud Storage"

  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.metadata.product_event_type = "storage.objects.get"
    $e.principal.user.userid = $user
    $e.target.resource.resource_type = "STORAGE_BUCKET"
    // Lọc truy cập ngoài giờ hành chính: trước 8h hoặc sau 18h (UTC+7)
    $hour = timestamp.get_hour($e.metadata.event_timestamp.seconds, "Asia/Ho_Chi_Minh")
    ($hour < 8 OR $hour >= 18)

  match:
    $user over 1h

  outcome:
    $access_count = count($e.metadata.id)

  condition:
    $e
}
```

### BigQuery SQL

```sql
-- Luật 2: Off-Hours Access Detection
-- Phát hiện truy cập ngoài giờ hành chính (trước 8h hoặc sau 18h, UTC+7)
SELECT
  protopayload_auditlog.authenticationInfo.principalEmail AS principal,
  TIMESTAMP_TRUNC(timestamp, HOUR) AS hour_window,
  EXTRACT(HOUR FROM timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh') AS hour_vn,
  COUNT(*) AS access_count,
  MIN(timestamp) AS first_access,
  MAX(timestamp) AS last_access
FROM
  `linen-flash-490013-u3.soc_audit_dataset.cloudaudit_googleapis_com_data_access_*`
WHERE
  protopayload_auditlog.methodName = 'storage.objects.get'
  AND (
    EXTRACT(HOUR FROM timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh') < 8
    OR EXTRACT(HOUR FROM timestamp AT TIME ZONE 'Asia/Ho_Chi_Minh') >= 18
  )
GROUP BY principal, hour_window, hour_vn
ORDER BY access_count DESC;
```

### Giải thích chuyển đổi

| Thành phần YARA-L | SQL tương ứng | Ghi chú |
|---|---|---|
| `timestamp.get_hour(...)` | `EXTRACT(HOUR FROM ... AT TIME ZONE)` | Trích giờ theo UTC+7 |
| `$hour < 8 OR $hour >= 18` | `WHERE EXTRACT(...) < 8 OR >= 18` | Lọc ngoài giờ hành chính |
| `match $user over 1h` | `TIMESTAMP_TRUNC(timestamp, HOUR)` | Hop → Tumbling (1 giờ) |
| `condition: $e` (không có ngưỡng) | Không cần `HAVING` | Chỉ cần 1 event là đủ |

---

## 4. Luật 3: Suspicious Tool Access Detection

**Mô tả:** Phát hiện truy cập từ Python SDK tự động, loại trừ gsutil CLI hợp lệ.  
**MITRE ATT&CK:** T1078 — Valid Accounts  
**Severity:** HIGH  
**Tương đương:** Context Enrichment Layer 3 — User Agent Analysis (Mục 3.4.2)

### YARA-L Rule

```yara
rule gcs_suspicious_tool_access {
  meta:
    author = "SOC Lab - KLTN 2026"
    description = "Phát hiện truy cập Cloud Storage bằng script Python tự động (không phải gsutil)"
    severity = "HIGH"
    mitre_attack = "T1078 - Valid Accounts"

  events:
    $e.metadata.event_type = "USER_RESOURCE_ACCESS"
    $e.metadata.product_event_type = "storage.objects.get"
    $e.principal.user.userid = $user
    $e.principal.ip = $ip
    $e.target.resource.resource_type = "STORAGE_BUCKET"
    // Phát hiện Python SDK nhưng loại trừ gsutil
    re.regex($e.network.http.user_agent, `python`) nocase
    not re.regex($e.network.http.user_agent, `gsutil`) nocase

  match:
    $user, $ip over 1h

  outcome:
    $access_count = count($e.metadata.id)

  condition:
    $e
}
```

### BigQuery SQL

```sql
-- Luật 3: Suspicious Tool Access Detection
-- Phân biệt Python SDK (gcloud-python) với gsutil CLI
-- Mở rộng cho forensic: không giới hạn cửa sổ thời gian,
-- GROUP BY thêm user_agent để phân tích chi tiết
SELECT
  protopayload_auditlog.authenticationInfo.principalEmail AS principal,
  protopayload_auditlog.requestMetadata.callerIp AS source_ip,
  protopayload_auditlog.requestMetadata.callerSuppliedUserAgent AS user_agent,
  COUNT(*) AS access_count,
  MIN(timestamp) AS first_access,
  MAX(timestamp) AS last_access
FROM
  `linen-flash-490013-u3.soc_audit_dataset.cloudaudit_googleapis_com_data_access_*`
WHERE
  protopayload_auditlog.methodName = 'storage.objects.get'
  AND LOWER(protopayload_auditlog.requestMetadata.callerSuppliedUserAgent) LIKE '%python%'
  AND LOWER(protopayload_auditlog.requestMetadata.callerSuppliedUserAgent) NOT LIKE '%gsutil%'
GROUP BY principal, source_ip, user_agent
ORDER BY access_count DESC;
```

### Giải thích chuyển đổi

| Thành phần YARA-L | SQL tương ứng | Ghi chú |
|---|---|---|
| `re.regex(..., 'python') nocase` | `LOWER(...) LIKE '%python%'` | Tìm User Agent chứa "python" |
| `not re.regex(..., 'gsutil')` | `NOT LIKE '%gsutil%'` | Loại trừ gsutil CLI |
| `match $user, $ip over 1h` | `GROUP BY principal, source_ip` | SQL bỏ cửa sổ 1h (mở rộng forensic) |
| — | `GROUP BY ... user_agent` | SQL thêm trường để phân tích chi tiết |

---

## 5. So sánh YARA-L vs SQL vs Alert Policy

| Tiêu chí | YARA-L (Chronicle) | SQL (BigQuery) | Alert Policy (Cloud Monitoring) |
|---|---|---|---|
| **Dữ liệu đầu vào** | UDM — chuẩn hóa tự động | Cloud Audit Log thô — ánh xạ thủ công | Log-based Metric — đếm từ Audit Log |
| **Cú pháp** | Khai báo, chuyên biệt bảo mật | Khai báo, đa mục đích | Cấu hình khai báo (Terraform) |
| **Tương quan đa sự kiện** | Native (nhiều biến `$e1`, `$e2`) | Cần `JOIN` phức tạp | Không hỗ trợ |
| **Cửa sổ thời gian** | **Hop window** (chồng lấn) | **Tumbling window** (không chồng lấn) | **Tumbling window** (`alignment_period`) |
| **Log Ingestion Latency** | Thấp — UDM đã chuẩn hóa | Không — batch hậu kỳ | **Cao** — dữ liệu chưa hoàn chỉnh |
| **Hiệu năng** | Streaming real-time | Batch query (điều tra hậu sự cố) | Gần real-time |
| **Chi phí** | License Chronicle (đắt) | BigQuery (1TB/tháng miễn phí) | Miễn phí (tích hợp GCP) |
| **Triển khai** | Alerting + Response tự động | Chỉ truy vấn — cần thêm logic | Alerting + Notification Channel |

---

## 6. Hạn chế của phương pháp chuyển đổi

### 6.1. Cửa sổ thời gian (Hop window vs Tumbling window)

`match $user over 1m` trong YARA-L tạo **hop window** (chồng lấn) — mọi chuỗi sự kiện liên tục trong 1 phút bất kỳ đều được đánh giá. SQL chỉ tạo được **tumbling window** (bucket cố định, không chồng lấn) qua `TIMESTAMP_TRUNC`.

**Ví dụ sai lệch:** 26 sự kiện trong khoảng 14:05:30–14:06:29 bị chia thành 2 bucket (mỗi bucket ~13 events, dưới ngưỡng 25) → SQL **bỏ sót**, YARA-L **phát hiện đúng**.

### 6.2. Phạm vi truy vấn Luật 3

YARA-L giới hạn `match $user, $ip over 1h` (cửa sổ 1 giờ), SQL không áp dụng cửa sổ — đếm toàn bộ lịch sử log. Khác biệt có chủ đích: SQL phục vụ mục đích **forensic** (điều tra toàn diện).

### 6.3. Kết luận

Kết quả BigQuery là **bằng chứng thực nghiệm** cho thấy logic phát hiện cốt lõi của YARA-L hợp lý trên Cloud Audit Log — mặc dù SQL chỉ mô phỏng gần đúng. Nếu triển khai trên Chronicle, hop window sẽ hiệu quả hơn, nhưng **chưa kiểm chứng thực nghiệm do giới hạn license**.
