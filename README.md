# 🛡️ Web Attack Detection ML System

Hệ thống phát hiện và phân loại tấn công web dựa trên Machine Learning (LightGBM Multi-Class) với kiến trúc 2 tầng chuẩn mực: **Unified Parser** $\rightarrow$ **30 Features Extractor** $\rightarrow$ **Security Classifier**.

---

## 📌 Điểm Nổi Bật

1. **Hỗ trợ 4 định dạng request**:
   - **Type 1 – Raw URL**: Phân tích URL và query parameters.
   - **Type 2 – Raw HTTP Request**: Phân tích request đầy đủ (Method, Path, Headers, Body).
   - **Type 3 – cURL Command**: Phân tích cú pháp tĩnh lệnh `curl` (xử lý cờ `-X`, `-H`, `-d`, `--get`, `--path-as-is`), **tuyệt đối không thực thi lệnh shell**.
   - **Type 4 – Access Log**: Phân tích log định dạng Nginx, Apache, IIS, CSIC.
2. **Kiến trúc 2 tầng độc lập**:
   - **Tầng 1 (Parser)**: Chuẩn hóa mọi định dạng về chung cấu trúc `NormalizedRequest` mà không can thiệp phán đoán nhãn.
   - **Tầng 2 (Detector)**: Trích xuất 30 đặc trưng chuyên sâu và định vị vị trí mã độc (`Threat Origin`: Body / Query / Path / Header).
3. **Phân loại 6 lớp tấn công (Multi-Class)**:
   - `0: Normal` (An toàn)
   - `1: SQL Injection`
   - `2: XSS (Cross-Site Scripting)`
   - `3: Command Injection`
   - `4: Path Traversal / LFI`
   - `5: Other Attack (SSTI / XXE / SSRF / NoSQLi)`
4. **Giao diện Web Dashboard**:
   - Thiết kế tối giản đen - trắng (Pure Minimalist B&W `#000000`), font chữ **Montserrat**.
   - Tab 1: Soi chi tiết cấu trúc JSON chuẩn hóa và chấm điểm đe dọa.
   - Tab 2: Quét file log (hỗ trợ kéo thả file `.log`, `.txt`, `.csv`) và xuất báo cáo CSV.

---

## 📂 Cấu Trúc Thư Mục

```
web_attack_detection_system/
├── models/                         # Thư mục chứa model ML đã huấn luyện
│   ├── best_model_multiclass.pkl   # Model LightGBM 6-class (Test Acc: 96.5%)
│   ├── feature_names.pkl           # Danh sách 30 đặc trưng
│   ├── label_map.pkl               # Bảng ánh xạ nhãn
│   └── model_metadata.json         # Siêu dữ liệu mô hình
├── request_parser.py               # Parser chuẩn hóa 4 định dạng request
├── detector.py                     # Trích xuất 30 features & Engine suy luận ML + CLI
├── web_app.py                      # Web Dashboard (Port 5000) & REST API
├── train_multiclass.py             # Script huấn luyện lại mô hình
├── build_dataset.py                # Script thu thập & chuẩn hóa bộ dữ liệu
├── lab89.ipynb                     # Jupyter Notebook toàn bộ quy trình & thực nghiệm
├── logsfile.txt                    # Log mẫu cURL (10 Normal + 10 Attack)
├── access.log                      # Log mẫu Nginx Web Server
├── testlog.log                     # Log mẫu benchmark CSIC Security
├── requirements.txt                # Thư viện phụ thuộc
├── run.bat                         # Phím tắt chạy nhanh trên Windows
└── README.md                       # Tài liệu hướng dẫn
```

---

## 🚀 Hướng Dẫn Cài Đặt & Sử Dụng

### 1. Cài đặt thư viện phụ thuộc
Yêu cầu Python >= 3.9:
```bash
pip install -r requirements.txt
```

### 2. Khởi chạy Web Dashboard
Chạy lệnh sau hoặc nhấp đúp vào file `run.bat`:
```bash
python web_app.py
```
Mở trình duyệt truy cập: **`http://localhost:5000`**

### 3. Sử dụng qua giao diện dòng lệnh (CLI)

* **Kiểm tra câu lệnh cURL**:
  ```bash
  python detector.py --curl "curl -i -X POST http://TARGET/login -d \"username=duy&password=DemoPass123\""
  ```
* **Kiểm tra URL**:
  ```bash
  python detector.py --url "https://example.com/search?q=<script>alert(1)</script>"
  ```
* **Kiểm tra Raw HTTP**:
  ```bash
  python detector.py --raw-http "POST /login HTTP/1.1\nHost: target.com\n\nusername=admin' OR 1=1--"
  ```
* **Quét file log**:
  ```bash
  python detector.py --log logsfile.txt
  ```
* **Chế độ nhập tương tác bàn phím trực tiếp**:
  ```bash
  python detector.py -i
  ```

---

## 📊 Hiệu Năng Mô Hình

* **Thuật toán**: LightGBM Multi-Class Classifier
* **Độ chính xác (Accuracy)**: **96.47%**
* **Nhận diện Tấn công vs Bình thường**: **96.65%**
* **Macro F1-Score**: **0.9690**
* **Thời gian suy luận (Inference Time)**: **< 1ms / request**

