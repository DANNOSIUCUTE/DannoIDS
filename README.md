<div align="center">

# DannoIDS: Web Attack Detection and Intrusion Detection System
### High-Performance Web Threat Detection Engine Powered by Multi-Class Machine Learning and Zero-Trust Request Normalization

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](requirements.txt)
[![Engine](https://img.shields.io/badge/ML%20Engine-LightGBM-brightgreen.svg)](#performance-and-benchmarks)
[![Accuracy](https://img.shields.io/badge/Test%20Accuracy-96.47%25-success.svg)](#performance-and-benchmarks)
[![F1-Macro](https://img.shields.io/badge/Macro%20F1-0.9690-green.svg)](#performance-and-benchmarks)
[![Latency](https://img.shields.io/badge/Inference-%3C1ms%20%2F%20req-orange.svg)](#performance-and-benchmarks)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](#license)

<br/>

[Overview](#overview) | [System Architecture](#system-architecture) | [Supported Input Formats](#supported-input-formats) | [30-Dimensional Feature Matrix](#30-dimensional-feature-matrix) | [Installation & Usage](#installation-and-usage) | [REST API Reference](#rest-api-reference) | [Performance Benchmarks](#performance-and-benchmarks)

---

</div>

## Overview

**DannoIDS** is an intelligent Web Application Intrusion Detection System (IDS) engineered to identify, classify, and localize web-based application attacks in real time.

Conventional Web Application Firewalls (WAFs) relying primarily on rigid regular expressions often suffer from high operational maintenance costs, bypasses via sophisticated evasion/obfuscation techniques, and elevated false positive rates on benign user traffic. DannoIDS addresses these challenges by combining a **deterministic, zero-trust input parser** with a **30-dimensional feature engineering pipeline** and a **LightGBM multi-class classification model**.

Operating at an inference latency of **less than 1 millisecond per request** (> 1,100 requests/second on a single CPU core), DannoIDS delivers high-throughput threat screening suitable for reverse proxies, API gateways, offline access log audits, and security operations centers (SOC).

---

## Key Capabilities

* **Strict Two-Stage Decoupled Pipeline**:
  * **Stage 1 (Unified Normalization)**: Converts heterogeneous input formats into an immutable, structured `NormalizedRequest` object. The parser performs syntactic restructuring only and does not make classification decisions.
  * **Stage 2 (Feature Extraction & ML Inference)**: Computes 30 lexical, statistical, encoding, and heuristic features, predicts multi-class threat probabilities, and isolates the specific attack injection location (`Threat Origin`).
* **Universal Multi-Format Ingestion**: Supports four common web input representations: Raw URLs, Raw HTTP requests (RFC 7230), cURL command strings (parsed via an abstract syntax tokenizer without shell execution), and web server access logs (Apache, Nginx, W3C).
* **6-Class Granular Threat Taxonomy**: Classifies traffic into six distinct categories: Normal traffic, SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection, Path Traversal / Local File Inclusion (LFI), and Other Advanced Attacks (SSTI, XXE, SSRF, NoSQLi).
* **Precise Threat Localization**: Identifies the exact component containing the malicious payload (`Request Body`, `Query Parameter`, `URI Path`, or `HTTP Headers`).
* **Heuristic False Positive Mitigation**: Employs context-aware boundary validation (e.g., regex word boundaries for command primitives such as `\bcat\b` and `\bcmd\b`) to ensure legitimate administrative and resource paths (such as `notification.php` or `application/json`) are never misclassified.
* **Self-Contained Minimalist Web Dashboard**: Pure black-and-white interface (`#000000` / `#ffffff`) rendered with the **Montserrat** typography system. Built entirely on Python standard library modules with zero third-party web framework dependencies.

---

## System Architecture

DannoIDS operates through an end-to-end, multi-stage processing pipeline:

```
+-----------------------------------------------------------------------------------+
|                            HETEROGENEOUS INPUT SOURCES                            |
|   [Type 1: Raw URL]  [Type 2: Raw HTTP]  [Type 3: cURL Command]  [Type 4: Logs]   |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|               STAGE 1: ZERO-TRUST PARSER & NORMALIZATION (request_parser.py)      |
|  * Static Tokenization & Decoding Sanitation (no shell execution / no eval)       |
|  * Standardized Output: NormalizedRequest Object                                  |
|    { method, url, path, query, headers, body, content_type, input_type }         |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|               STAGE 2: FEATURE ENGINEERING PIPELINE (detector.py)                 |
|  * 7 Structural & Dimension Metrics (Length, Path Depth, Parameter Lengths)       |
|  * 5 Statistical & Entropy Metrics (Shannon Entropy, Special Ratio, Digits)       |
|  * 5 Obfuscation & Encoding Metrics (Percent Encoded, Double Encoded, Null Byte)  |
|  * 13 Threat Heuristics (SQLi, XSS, Cmd, Traversal, SSTI, XXE, SSRF, NoSQL)       |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|               STAGE 3: MULTI-CLASS ML INFERENCE ENGINE (LightGBM)                 |
|  * Softmax Probability Distribution across 6 Attack Classes                       |
|  * Threat Origin Localization (Body, Query String, Path, Headers)                 |
|  * Context-Aware Validation & False-Positive Suppression Heuristics              |
+-----------------------------------------+-----------------------------------------+
                                          |
                                          v
+-----------------------------------------------------------------------------------+
|                               OUTPUT INTERFACES                                   |
|       [Web Dashboard :5000]       [REST API JSON]       [CLI Batch Scanner]       |
+-----------------------------------------------------------------------------------+
```

---

## Supported Input Formats

Regardless of how raw traffic is provided, Stage 1 guarantees complete normalization into a uniform schema:

| Format Type | Description | Representative Input Example |
| :--- | :--- | :--- |
| **Type 1: Raw URL** | Standalone URL parsing. Splits scheme, network location, path hierarchy, and query parameters. | `https://example.com/search?q=test&page=1` |
| **Type 2: Raw HTTP Request** | Full RFC 7230 request parser. Extracts method, target URI, HTTP version, key-value headers, and raw body. | `POST /login HTTP/1.1`<br>`Host: target.com`<br>`Content-Type: application/x-www-form-urlencoded`<br><br>`user=admin&pass=123` |
| **Type 3: cURL Command** | Abstract syntax parser. Extracts flags (`-X`, `-H`, `-d`, `--data-urlencode`, `-G`, `--path-as-is`). Never executes commands. | `curl -i -X POST http://target/login -d "username=admin&password=123"` |
| **Type 4: Access Log** | Parses web server access records across Common Log Format (CLF), Combined Log Format, and custom formats. | `192.168.1.10 - - [14/Nov/2026:10:00:00 +0000] "GET /app?id=1 HTTP/1.1" 200 4502` |

### Normalized Request Schema (`NormalizedRequest`)

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

## Attack Classification Taxonomy

The underlying multi-class classifier categorizes requests into six mutually exclusive classes:

| Class ID | Attack Label | Detection Focus | Exploit Signature Examples |
| :---: | :--- | :--- | :--- |
| **0** | **Normal** | Legitimate application traffic, valid authentication attempts, static assets. | Standard forms, benign API JSON payloads, image/asset fetches. |
| **1** | **SQL Injection** | SQL query tampering, authentication bypass, data exfiltration via subqueries. | `' UNION SELECT null, username, password FROM users--`, `OR 1=1` |
| **2** | **Cross-Site Scripting** | Client-side script injection via unescaped inputs (reflected, stored, DOM-based). | `<script>alert(document.cookie)</script>`, `<img src=x onerror=alert(1)>` |
| **3** | **Command Injection** | Execution of arbitrary operating system commands through unvalidated arguments. | `; cat /etc/passwd`, `\| ping -c 4 127.0.0.1`, `&& whoami` |
| **4** | **Path Traversal / LFI** | Unauthorized file system traversal to read sensitive server configuration files. | `../../../../etc/passwd`, `..%2f..%2fwindows/win.ini` |
| **5** | **Other Attack** | Advanced injection vectors: SSTI, XML External Entity (XXE), SSRF, NoSQL injection. | `{{7*7}}`, `<!ENTITY xxe SYSTEM "file:///etc/passwd">`, `$where` |

---

## 30-Dimensional Feature Matrix

Every incoming request is transformed into a dense, 30-dimensional numerical feature vector:

### 1. Structural and Morphological Features
* `length`: Total character length of the normalized request.
* `path_length`: Length of the URI path component.
* `query_length`: Total length of the query parameter string.
* `path_depth`: Directory hierarchy depth (count of `/` delimiters).
* `max_param_length`: Maximum length observed across all input parameters.
* `avg_param_length`: Arithmetic mean of parameter lengths.
* `uppercase_ratio`: Ratio of uppercase characters to total length (frequently used in WAF evasion techniques, e.g., `sElEcT`).

### 2. Statistical and Information Entropy Features
* `special_char_count`: Total count of special characters (`'`, `"`, `<`, `>`, `;`, `$`, `|`, `&`, etc.).
* `special_ratio`: Proportion of special characters relative to request length.
* `num_digits`: Absolute count of numeric characters (`0-9`).
* `num_params`: Total count of query parameters and form body keys.
* `entropy`: Shannon Information Entropy of the request text (effective for identifying encrypted, encoded, or high-randomness shellcode).
* `non_ascii_count`: Count of non-ASCII characters outside the standard printable range.

### 3. Obfuscation and Encoding Indicators
* `percent_encoding`: Frequency of hexadecimal URL percent-encoding tokens (`%20`, `%27`, etc.).
* `has_encoded`: Binary flag indicating the presence of percent-encoded sequences.
* `double_encoded`: Binary indicator detecting double URL encoding attempts (e.g., `%2527`).
* `has_null_byte`: Binary indicator for poison null byte injection (`%00`).
* `has_unicode_escape`: Binary indicator for unicode escape notation (`\u0027`).

### 4. Threat Heuristic and Signature Patterns
* `sql_keywords`: Frequency count of standard SQL keywords (`union`, `select`, `information_schema`, etc.).
* `js_keywords`: Frequency count of script and browser DOM keywords (`<script`, `onerror`, `onload`, `eval`).
* `cmd_keywords`: Frequency count of OS command primitives bounded by word boundaries (`\bcat\b`, `\bwhoami\b`, `\bcmd\b`).
* `path_traversal`: Frequency of directory traversal patterns (`../` or `..\`).
* `single_quotes`: Total count of single quote characters (`'`).
* `is_brute`: Metric capturing repetitive parameter patterns indicative of fuzzing or brute-force attempts.
* `has_path_traversal`: Binary flag indicating directory traversal presence.
* `has_admin`: Binary flag denoting access to sensitive administrative routes (`/admin`, `/root`, `/config`).
* `nosql_keywords`: Detection of NoSQL injection syntax (`$where`, `$ne`, `$regex`).
* `ssti_patterns`: Detection of server-side template injection delimiters (`${...}`, `{{...}}`, `<%=...%>`).
* `xxe_patterns`: Detection of XML entity declarations (`<!ENTITY`, `SYSTEM`).
* `ssrf_patterns`: Detection of internal IP ranges and sensitive schemes (`169.254.169.254`, `127.0.0.1`, `file://`).

---

## Directory Structure

```
DannoIDS/
├── models/                               # Pretrained ML artifacts and metadata
│   ├── best_model_multiclass.pkl         # Serialized LightGBM 6-class model
│   ├── best_model_random_forest.pkl      # Benchmark Random Forest baseline model
│   ├── feature_names.pkl                 # Serialized list of 30 feature names
│   ├── label_map.pkl                     # Class ID to string label mappings
│   └── model_metadata.json               # Hyperparameters and evaluation metrics
│
├── request_parser.py                     # Deterministic 4-format normalization module
├── detector.py                           # Feature engineering, ML inference engine, CLI
├── web_app.py                            # Standalone Web Dashboard & REST API server
│
├── build_dataset.py                      # Dataset generation and synthesis pipeline
├── train_multiclass.py                   # LightGBM training and validation script
├── lab89.ipynb                           # Research notebook for EDA and experiments
│
├── logsfile.txt                          # Verification test log (10 Normal + 10 Attack cURL commands)
├── access.log                            # Sample Nginx/Apache web server access log
├── testlog.log                           # Standard CSIC benchmark test log
│
├── run.bat                               # Windows one-click interactive launcher
├── run.sh                                # Linux/macOS one-click interactive launcher
├── requirements.txt                      # Minimal dependencies list
├── README.md                             # Primary technical documentation (English)
└── README_VN.md                          # Vietnamese documentation reference
```

---

## Installation and Usage

### Prerequisites
* **Python Runtime**: Version `>= 3.9` (Recommended: Python 3.10 or 3.11).
* **Operating Systems**: Windows 10/11, Linux (Ubuntu/Debian, CentOS, RHEL), macOS.

### Installation

```bash
# Clone or navigate to the project directory
cd D:\DannoIDS

# Install required dependencies
pip install -r requirements.txt
```

> [!NOTE]
> Dependencies are strictly limited to core data processing and machine learning packages (`numpy`, `pandas`, `scikit-learn`, `lightgbm`, `joblib`). The Web Dashboard and API server run natively on Python's built-in `http.server`, `urllib`, and `shlex` modules without requiring external web frameworks.

---

### Running the Web Dashboard

#### Option A: One-Click Launcher
* **Windows**: Double-click `run.bat` and enter option `1`.
* **Linux / macOS**: Execute `./run.sh` and select option `1`.

#### Option B: Command-Line Execution
```bash
python web_app.py --port 5000
```
Open your browser and navigate to: **`http://localhost:5000`**

---

### Command-Line Interface (CLI Scanner)

The `detector.py` module provides a comprehensive CLI for ad-hoc inspection and log auditing:

#### 1. Analyze a cURL Command:
```bash
python detector.py --curl "curl -i -X POST http://TARGET/login -d \"username=duy&password=DemoPass123\""
```

#### 2. Analyze a URL:
```bash
python detector.py --url "https://example.com/search?q=<script>alert(1)</script>"
```

#### 3. Analyze a Raw HTTP Request:
```bash
python detector.py --raw-http "GET /index.php?id=1' UNION SELECT null,password FROM users-- HTTP/1.1\nHost: target.com"
```

#### 4. Audit a Web Server Access Log File:
```bash
python detector.py --log logsfile.txt
```

*Sample CLI output:*
```text
Scanning log file: logsfile.txt ...
Total requests    : 20
Attack detected   : 10
Normal requests   : 10
Attack ratio      : 50.0%
Threat breakdown:
  - SQL Injection                 : 5
  - Other Attack (SSTI/XXE/SSRF)  : 2
  - Path Traversal / LFI          : 2
  - XSS                           : 1
```

#### 5. Interactive Terminal Shell:
```bash
python detector.py -i
```

---

## REST API Reference

DannoIDS exposes a lightweight REST API for automated integration into CI/CD pipelines, reverse proxies, and SIEM architectures:

### 1. Predict Single Request (`POST /api/predict`)

* **Endpoint**: `http://localhost:5000/api/predict`
* **Method**: `POST`
* **Content-Type**: `application/json`

#### Request Payload:
```json
{
  "input": "curl -X POST http://example.com/login -d \"user=admin' OR '1'='1&pass=123\"",
  "input_type": "auto",
  "threshold": 0.35
}
```

#### Response Payload:
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

### 2. Log Analysis API (`POST /api/analyze-log`)
Accepts raw log file streams or text chunks and returns an aggregated breakdown of detected threats, timestamps, client IPs, and classification categories.

---

## Performance and Benchmarks

The model was evaluated against an aggregated benchmark corpus comprising **131,053 HTTP request records**, incorporating diverse real-world traffic profiles from benchmark datasets including CSIC 2010, CIC-IDS-2017, and SecLists payload corpora:

| Evaluation Metric | Measured Benchmark Value |
| :--- | :---: |
| **Model Architecture** | **LightGBM Multi-Class Classifier** |
| **Training Dataset Size** | **131,053 records** |
| **Model Training Duration** | **3.44 seconds** |
| **Overall Multi-Class Test Accuracy** | **96.47%** |
| **Binary Classification Accuracy (Attack vs. Normal)** | **96.65%** |
| **Macro-Averaged F1-Score** | **0.9690** |
| **Average Inference Latency** | **< 0.85 ms / request** |
| **Processing Throughput** | **> 1,100 requests / second (Single CPU Core)** |

---

## Web Dashboard and Interface Design

The DannoIDS Web Dashboard is engineered around a **high-contrast monochrome design philosophy (`#000000` / `#ffffff`)**:

* **Clean Typography Hierarchy**: Employs **Montserrat** for interface typography and **JetBrains Mono** for payload rendering and code segments.
* **Two-Stage Visual Inspection Workflow**:
  * **Stage 1 (Normalized Structure)**: Inspects the sanitized `NormalizedRequest` output with one-click JSON clipboard export.
  * **Stage 2 (Security Assessment)**: Displays the primary threat classification badge, detected payload location (`Threat Origin`), multi-class probability breakdown, and a complete table of the 30 extracted feature values.
* **High-Volume Log Auditing Tab**: Supports drag-and-drop ingestion of `.log`, `.txt`, and `.csv` files with client-side pagination, category filtering, and one-click CSV report export.

---

## Ethical and Security Considerations

DannoIDS is developed exclusively for defensive cybersecurity research, academic study, and authorized operational monitoring. Users are responsible for ensuring that this software is operated in strict compliance with applicable local laws and organizational policies. The authors assume no liability for misuse or damages resulting from unauthorized deployment.

---

## License

This project is distributed under the terms of the **MIT License**. Refer to the project license documentation for full terms and conditions.

---

<div align="center">

**DannoIDS: Empowering Modern Web Defense with High-Performance Machine Learning**

</div>
