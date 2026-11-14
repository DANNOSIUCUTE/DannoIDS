<div align="center">

# 🛡️ DannoIDS — Web Attack Detection & Intrusion Detection System
### *Intelligent Web Threat Detection Engine Powered by Multi-Class Machine Learning & Zero-Trust Normalization*

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg?logo=python&logoColor=white)](#-yêu-cầu-hệ-thống)
[![Engine](https://img.shields.io/badge/ML%20Engine-LightGBM-brightgreen.svg)](#-hiệu-năng--thực-nghiệm)
[![Accuracy](https://img.shields.io/badge/Test%20Accuracy-96.47%25-success.svg)](#-hiệu-năng--thực-nghiệm)
[![F1-Macro](https://img.shields.io/badge/Macro%20F1-0.9690-green.svg)](#-hiệu-năng--thực-nghiệm)
[![Latency](https://img.shields.io/badge/Inference-%3C1ms%20%2F%20req-orange.svg)](#-hiệu-năng--thực-nghiệm)
[![UI](https://img.shields.io/badge/Theme-Pure%20Minimalist%20B%26W-black.svg)](#-giao-diện-web-dashboard)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](#-bản-quyền--giấy-phép)

<br/>

[Tổng Quan](#-tổng-quan-dự-án) • [Kiến Trúc](#-kiến-trúc-hệ-thống) • [4 Định Dạng Đầu Vào](#-hỗ-trợ-4-định-dạng-đầu-vào) • [Bộ 30 Đặc Trưng](#-bộ-30-đặc-trưng-chuyên-sâu) • [Cài Đặt & Sử Dụng](#-cài-đặt--hướng-dẫn-sử-dụng) • [REST API](#-tài-liệu-rest-api) • [Benchmarks](#-hiệu-năng--thực-nghiệm)

---

</div>

## 📖 Tổng Quan Dự Án

**DannoIDS** là hệ thống Phát hiện Xâm nhập Ứng dụng Web (Web Application IDS) thế hệ mới, kết hợp giữa kỹ thuật **Zero-Trust Input Normalization** và mô hình học máy **LightGBM Multi-Class**. 

Khác với các công cụ WAF dựa trên luật (rule-based) truyền thống dễ bị bypass bởi obfuscation hoặc gây ra nhiều cảnh báo giả (false positives), DannoIDS phân tích các thuộc tính từ vựng, hình thái học, cấu trúc mã hóa và entropy thông tin của request để đưa ra phán đoán chính xác trong thời gian thực (**< 1ms/request**).

### ✨ Đặc Điểm Nổi Bật

* **Kiến Trúc Tách Biệt Độc Lập 2 Tầng**:
  * **Tầng 1 (Parser)**: Chuẩn hóa dữ liệu về định dạng thống nhất `NormalizedRequest`. Parser tuyệt đối **không** can thiệp phán đoán request là Normal hay Attack.
  * **Tầng 2 (Detector & Feature Extractor)**: Trích xuất 30 đặc trưng kỹ thuật số, định vị thành phần độc hại (`Threat Origin`), tính toán xác suất phân loại đa lớp.
* **Hỗ Trợ 4 Định Dạng Đầu Vào Đa Dạng**: Phân tích trực tiếp Raw URL, Raw HTTP Request, Access Logs (Apache, Nginx, W3C) và lệnh cURL tĩnh (tuyệt đối không thực thi shell script).
* **Phân Loại 6 Nhãn Đe Dọa (Multi-Class)**: Không chỉ dừng lại ở cảnh báo nhị phân (Attack vs Normal), DannoIDS phân định chi tiết loại hình tấn công (SQLi, XSS, Cmd Injection, Path Traversal, SSTI/XXE).
* **Định Vị Vị Trí Tấn Công (Threat Localization)**: Chỉ rõ payload nguy hiểm xuất hiện ở đâu (`URI Path`, `Query String`, `Request Body`, hay `HTTP Headers`).
* **Triệt Tiêu Cảnh Báo Giả (False Positive Mitigation)**: Tinh chỉnh ranh giới từ vựng (`\bcat\b`, `\bcmd\b`) giúp các đường dẫn hợp lệ (ví dụ: `notification.php`, `application/json`) không bị nhận diện nhầm là Command Injection.
* **Giao Diện Web Minimalist Độc Lập**: Giao diện thuần đen - trắng (`#000000` / `#ffffff`), typography hiện đại font **Montserrat**, không phụ thuộc framework web bên ngoài (chạy trực tiếp bằng Python standard library).

---

## 🏗️ Kiến Trúc Hệ Thống

DannoIDS vận hành theo quy trình xử lý 3 giai đoạn khép kín và an toàn:

```
+-----------------------------------------------------------------------------------+
|                            ĐẦU VÀO ĐA DẠNG (INPUT SOURCES)                        |
|   [Type 1: Raw URL]  [Type 2: Raw HTTP]  [Type 3: cURL Command]  [Type 4: Logs]   |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                 GIAI ĐOẠN 1: ZERO-TRUST PARSER (request_parser.py)                 |
|  * Static Tokenization & Obfuscation Cleanup (không thực thi lệnh shell)          |
|  * Trích xuất & cấu trúc hóa thành: NormalizedRequest Object                      |
|    { method, url, path, query, headers, body, content_type, input_type }         |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|               GIAI ĐOẠN 2: FEATURE ENGINEERING (30 FEATURES) (detector.py)        |
|  * 7 Đặc trưng Chiều dài & Cấu trúc (Length, Path Depth, Param Lengths,...)        |
|  * 5 Đặc trưng Thống kê & Phân bố Ký tự (Special Ratio, Entropy, Digits,...)       |
|  * 5 Đặc trưng Mã hóa & Obfuscation (URL Encoded, Double Encoded, Null Byte,...)  |
|  * 13 Dấu hiệu Cú pháp Tấn công (SQLi, XSS, Cmd, Traversal, SSTI, XXE, SSRF,...)  |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|              GIAI ĐOẠN 3: MULTI-CLASS ML INFERENCE ENGINE (LightGBM)              |
|  * Phân phối xác suất 6 phân lớp (Softmax Probabilities)                         |
|  * Định vị nguồn đe dọa (Threat Origin: Body, Query, Path, Header)                |
|  * Xác thực Heuristics & Giảm thiểu False Positive                               |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                           ĐẦU RA VÀ TÍCH HỢP (OUTPUTS)                            |
|       [Web Dashboard :5000]       [REST API JSON]       [CLI Batch Scanner]       |
+-----------------------------------------------------------------------------------+
```

---

## 🎯 Hỗ Trợ 4 Định Dạng Đầu Vào

Tất cả các định dạng sau khi qua bộ tiền xử lý đều được quy đổi về cấu trúc chuẩn:

| Định dạng | Mô tả kỹ thuật | Ví dụ thực tế |
| :--- | :--- | :--- |
| **Type 1 – Raw URL** | Phân tích URL độc lập, tách biệt giao thức, domain, URI path và query string. | `https://example.com/search?q=test&page=1` |
| **Type 2 – Raw HTTP Request** | Bóc tách đầy đủ RFC 7230: HTTP Method, Target Path, Protocol, Headers và Request Body. | `POST /api/v1/auth HTTP/1.1`<br>`Host: api.site.com`<br>`Content-Type: application/json`<br><br>`{"user":"admin"}` |
| **Type 3 – cURL Command** | Parser tĩnh an toàn qua Lexer/Tokenizer (hỗ trợ `-X`, `-H`, `-d`, `--data-urlencode`, `-G`, `--path-as-is`, boolean flags). **Không dùng `eval()` / `bash`**. | `curl -i -X POST http://target/login -d "username=admin&password=123"` |
| **Type 4 – Access Log** | Phân tích nhật ký máy chủ web (Common Log Format, Combined Log Format của Nginx, Apache, IIS). | `192.168.1.100 - - [14/Nov/2026:10:00:00 +0700] "GET /index.php?id=1 HTTP/1.1" 200 4502` |

### Cấu Trúc Dữ Liệu Sau Chuẩn Hóa (`NormalizedRequest`)

```json
{
  "input_type": "curl",
  "method": "POST",
  "url": "http://TARGET/login",
  "path": "/login",
  "query": {},
  "headers": {},
  "body": "username=duy&password=DemoPass123",
  "content_type": "application/x-www-form-urlencoded"
}
```

---

## 🏷️ Danh Mục Phân Loại Tấn Công (6 Classes)

Mô hình phân loại đa lớp của DannoIDS nhận diện 6 danh mục tấn công với độ chính xác cao:

| ID | Nhãn Phân Loại | Ký Hiệu | Ví Dụ Đặc Trưng |
| :---: | :--- | :---: | :--- |
| **0** | **Normal** | `Normal` | Lưu lượng hợp lệ, biểu mẫu đăng nhập, truy vấn dữ liệu chuẩn. |
| **1** | **SQL Injection** | `SQLi` | `' UNION SELECT null, username, password FROM users--`, `OR 1=1` |
| **2** | **Cross-Site Scripting** | `XSS` | `<script>alert(document.cookie)</script>`, `<svg/onload=confirm()>` |
| **3** | **Command Injection** | `Cmd_Inj` | `; cat /etc/passwd`, `| ping -c 4 127.0.0.1`, `& whoami` |
| **4** | **Path Traversal / LFI** | `Traversal` | `../../../../etc/passwd`, `..%2f..%2fwindows/win.ini` |
| **5** | **Other Attack** | `Other` | Server-Side Template Injection (`{{7*7}}`), XXE Injection, SSRF, NoSQLi |

---

## 🔬 Bộ 30 Đặc Trưng Chuyên Sâu (Feature Matrix)

Hệ thống trích xuất 30 đặc trưng toán học và ngữ nghĩa từ các phần tử của request:

```text
[Chiều Dài & Hình Thái]
  1. length               : Tổng chiều dài toàn bộ request chuỗi
  2. path_length          : Chiều dài của URI path
  3. query_length         : Chiều dài của chuỗi Query Parameter
  4. path_depth           : Độ sâu phân cấp thư mục (số lượng dấu /)
  5. max_param_length     : Chiều dài lớn nhất của một tham số bất kỳ
  6. avg_param_length     : Chiều dài trung bình của các tham số
  7. uppercase_ratio      : Tỷ lệ ký tự viết hoa (thường xuất hiện khi né WAF: sElEcT)

[Thống Kê & Entropy Ký Tự]
  8. special_char_count   : Tổng số ký tự đặc biệt (', ", <, >, ;, $, |, &,...)
  9. special_ratio        : Tỷ lệ ký tự đặc biệt trên tổng độ dài
 10. num_digits           : Số lượng ký tự số
 11. num_params           : Số lượng tham số đầu vào
 12. entropy              : Độ hỗn loạn thông tin Shannon Entropy (phát hiện shellcode/token)
 13. non_ascii_count      : Số lượng ký tự ngoài bảng mã chuẩn ASCII

[Mã Hóa & Kỹ Thuật Lẩn Tránh]
 14. percent_encoding     : Số lượng dấu mã hóa phần trăm (%20, %27,...)
 15. has_encoded          : Cờ nhị phân phát hiện có dữ liệu URL encoded
 16. double_encoded       : Phát hiện kỹ thuật Double Encoding (%2527)
 17. has_null_byte        : Dấu hiệu kỹ thuật Poison Null Byte (%00)
 18. has_unicode_escape   : Dấu hiệu ký tự Unicode Escape (\u0027)

[Dấu Hiệu & Mẫu Cú Pháp Tấn Công]
 19. sql_keywords         : Đếm từ khóa SQL (union, select, from, information_schema,...)
 20. js_keywords          : Đếm từ khóa JavaScript / HTML (<script, onerror, onload, alert,...)
 21. cmd_keywords         : Đếm từ khóa lệnh OS có biên từ (\bcat\b, \bwhoami\b, \bcmd\b,...)
 22. path_traversal       : Tần suất xuất hiện mẫu ../ hoặc ..\\
 23. single_quotes        : Số lượng dấu nháy đơn (')
 24. is_brute             : Dấu hiệu tấn công Brute Force / Fuzzing lặp lại
 25. has_path_traversal   : Cờ nhị phân phát hiện Directory Traversal
 26. has_admin            : Sự xuất hiện của đường dẫn nhạy cảm (/admin, /root, /config)
 27. nosql_keywords       : Mẫu truy vấn NoSQL Injection ($where, $ne, $regex)
 28. ssti_patterns        : Mẫu template engine (${...}, {{...}}, <%=...%>)
 29. xxe_patterns         : Mẫu thực thể XML độc hại (<!ENTITY, SYSTEM)
 30. ssrf_patterns        : Dấu hiệu truy xuất tài nguyên nội bộ (169.254.169.254, 127.0.0.1, file://)
```

---

## 📁 Cấu Trúc Thư Mục Dự Án

```
DannoIDS/
├── models/                               # Lưu trữ mô hình ML & siêu dữ liệu
│   ├── best_model_multiclass.pkl         # Trọng số LightGBM 6 phân lớp
│   ├── best_model_random_forest.pkl      # Mô hình đối sánh Random Forest
│   ├── feature_names.pkl                 # Danh sách 30 tên đặc trưng chuẩn hóa
│   ├── label_map.pkl                     # Bảng ánh xạ nhãn ID -> Tên tấn công
│   └── model_metadata.json               # Báo cáo thông số & độ chính xác mô hình
│
├── request_parser.py                     # Bộ tiền xử lý & chuẩn hóa 4 định dạng
├── detector.py                           # Feature Extractor + Inference Engine + CLI
├── web_app.py                            # Web Dashboard độc lập & REST API server
│
├── build_dataset.py                      # Kịch bản sinh & mở rộng tập dữ liệu 131k dòng
├── train_multiclass.py                   # Quy trình huấn luyện mô hình LightGBM
├── lab89.ipynb                           # Jupyter Notebook thực nghiệm & trực quan hóa
│
├── logsfile.txt                          # File log mẫu kiểm thử (10 Normal + 10 Attack)
├── access.log                            # Mẫu log Web Server Nginx/Apache thực tế
├── testlog.log                           # Mẫu log benchmark quốc tế (CSIC Dataset)
│
├── run.bat                               # Khởi chạy nhanh 1-Click (Windows)
├── run.sh                                # Khởi chạy nhanh 1-Click (Linux/macOS)
├── requirements.txt                      # Danh sách các gói thư viện Python
└── README.md                             # Tài liệu kỹ thuật dự án
```

---

## ⚡ Cài Đặt & Hướng Dẫn Sử Dụng

### 1. Yêu Cầu Môi Trường
* **Python**: Phiên bản `>= 3.9` (Khuyến nghị Python 3.10 / 3.11).
* **Hệ điều hành**: Windows 10/11, Ubuntu/Debian Linux, macOS.

### 2. Cài Đặt Thư Viện

```bash
# Di chuyển vào thư mục dự án
cd D:\DannoIDS

# Cài đặt các phụ thuộc
pip install -r requirements.txt
```

> [!NOTE]
> File `requirements.txt` chỉ bao gồm các thư viện xử lý dữ liệu và học máy cốt lõi (`numpy`, `pandas`, `scikit-learn`, `lightgbm`, `joblib`). Máy chủ Web và Parser chạy hoàn toàn trên chuẩn thư viện gốc của Python (`http.server`, `urllib`, `shlex`), không cần cài đặt thêm framework nặng như Flask hay Django.

---

### 3. Khởi Chạy Web Dashboard

* **Cách 1: Sử dụng Script 1-Click**
  * Trên **Windows**: Bấm đúp vào file `run.bat` $\rightarrow$ Nhấn phím `1`.
  * Trên **Linux / macOS**: Chạy lệnh `./run.sh` $\rightarrow$ Chọn số `1`.
* **Cách 2: Chạy trực tiếp qua dòng lệnh**
  ```bash
  python web_app.py --port 5000
  ```
* Mở trình duyệt và truy cập: **`http://localhost:5000`**

---

### 4. Sử Dụng Giao Diện Dòng Lệnh (CLI Scanner)

DannoIDS cung cấp giao diện CLI mạnh mẽ, hỗ trợ kiểm tra tức thì nhiều ngữ cảnh khác nhau:

#### A. Phân tích lệnh cURL:
```bash
python detector.py --curl "curl -i -X POST http://TARGET/login -d \"username=duy&password=DemoPass123\""
```

#### B. Phân tích URL:
```bash
python detector.py --url "https://example.com/search?q=<script>alert(1)</script>"
```

#### C. Phân tích Raw HTTP Request:
```bash
python detector.py --raw-http "GET /index.php?id=1' UNION SELECT null,password FROM users-- HTTP/1.1\nHost: target.com"
```

#### D. Quét toàn bộ file Log:
```bash
python detector.py --log logsfile.txt
```
*Kết quả mẫu xuất ra console:*
```text
Dang quet file log: logsfile.txt ...
Tong so requests : 20
So attack        : 10
So normal        : 10
Ty le attack     : 50.0%
Phan loai attack:
  - SQL Injection                 : 5
  - Other Attack (SSTI/XXE/SSRF)  : 2
  - Path Traversal / LFI          : 2
  - XSS                           : 1
```

#### E. Chế độ nhập tương tác bàn phím (Interactive Shell):
```bash
python detector.py -i
```

---

## 🔌 Tài Liệu REST API

DannoIDS tích hợp sẵn REST API chuẩn JSON giúp dễ dàng nhúng vào các hệ thống SIEM, Reverse Proxy hoặc API Gateway:

### 1. Phân Tích Request Đơn Lẻ (`POST /api/predict`)

* **Endpoint**: `http://localhost:5000/api/predict`
* **Method**: `POST`
* **Headers**: `Content-Type: application/json`

#### Request Body mẫu:
```json
{
  "input": "curl -X POST http://example.com/login -d \"user=admin' OR '1'='1&pass=123\"",
  "input_type": "auto",
  "threshold": 0.35
}
```

#### Response JSON mẫu:
```json
{
  "is_attack": true,
  "label": "Attack",
  "attack_type": "SQL Injection",
  "label_id": 1,
  "probability": 0.9984,
  "threat_locations": ["Request Body"],
  "normalized_request": {
    "input_type": "curl",
    "method": "POST",
    "url": "http://example.com/login",
    "path": "/login",
    "query": {},
    "headers": {},
    "body": "user=admin' OR '1'='1&pass=123",
    "content_type": "application/x-www-form-urlencoded"
  },
  "class_probabilities": {
    "Normal": 0.0016,
    "SQL Injection": 0.9984,
    "XSS": 0.0,
    "Command Injection": 0.0,
    "Path Traversal / LFI": 0.0,
    "Other Attack (SSTI/XXE/SSRF)": 0.0
  }
}
```

---

## 📊 Hiệu Năng & Thực Nghiệm

Mô hình được huấn luyện và đánh giá trên bộ dữ liệu kiểm thử tổng hợp gồm **131,053 mẫu request**, bao gồm lưu lượng web thực tế từ các bộ dataset nổi tiếng thế giới (CSIC 2010 HTTP Dataset, CIC-IDS-2017, SecLists Web Payloads):

| Chỉ Số Đánh Giá (Metric) | Kết Quả Đạt Được |
| :--- | :---: |
| **Mô hình Thuật toán** | **LightGBM Multi-Class Classifier** |
| **Kích thước Dữ liệu Huấn Luyện** | **131,053 dòng** |
| **Thời gian Huấn luyện (Training Time)** | **3.44 giây** |
| **Độ chính xác Tổng thể (Multi-Class Test Accuracy)** | **96.47%** |
| **Nhận diện Nhị phân (Attack vs Normal)** | **96.65%** |
| **Macro F1-Score** | **0.9690** |
| **Thời gian Suy luận Trung bình (Inference Latency)** | **< 0.85 ms / request** |
| **Tốc độ Xử lý (Throughput)** | **> 1,100 requests / giây (đơn luồng CPU)** |

---

## 🎨 Giao Diện Web Dashboard

Giao diện Web của DannoIDS được thiết kế theo trường phái **Dark Minimalist (`#000000` / `#ffffff`)**:
* **Typography**: Sử dụng font chữ hiện đại **Montserrat** cho tiêu đề & nhãn, kết hợp font đơn cách **JetBrains Mono** cho phần hiển thị mã nguồn và payload.
* **Trực quan hóa 2 Giai đoạn**:
  * **Stage 1 (Normalized Data)**: Hiển thị cấu trúc JSON chuẩn hóa sau khi tách từ cURL/Log, tích hợp nút sao chép nhanh 1 chạm.
  * **Stage 2 (Security Assessment)**: Hiển thị thẻ trạng thái đe dọa (An toàn / Tấn công), chỉ rõ xuất xứ payload độc hại (`Threat Origin`), bảng xác suất 6 phân lớp và thống kê chi tiết 30 đặc trưng.
* **Chế độ Phân tích Tệp Log hàng loạt**: Hỗ trợ kéo thả file log dung lượng lớn, phân trang mượt mà, lọc dữ liệu theo nhóm tấn công và xuất kết quả báo cáo ra file `.CSV`.

---

## 🛡️ Tuyên Bố Miễn Trừ & Đạo Đức An Toàn

Dự án **DannoIDS** được phát triển nhằm phục vụ mục đích nghiên cứu học thuật, kiểm thử phòng thủ (Defensive Security) và nâng cao năng lực giám sát an toàn thông tin cho hệ thống máy chủ web. Tác giả không chịu trách nhiệm đối với bất kỳ hành vi lạm dụng công cụ nào nhằm mục đích tấn công hoặc can thiệp trái phép vào các hệ thống chưa được cấp quyền.

---

<div align="center">

**DannoIDS — Empowering Modern Web Defense with Machine Learning**  
*Phát triển bởi đội ngũ nghiên cứu ATTT & Machine Learning.*

</div>
