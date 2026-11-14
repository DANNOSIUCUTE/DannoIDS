"""
detector.py - Web Attack Detection Engine (v3 Multi-Class Edition)
Features: 30 engineered features (v1 + v2 modern attack vectors)
Input formats supported:
  - Type 1: Raw URL
  - Type 2: Raw HTTP Request
  - Type 3: cURL Command
  - Type 4: Access Log
"""

import re
import math
import os
import json
import joblib
import pandas as pd
import numpy as np
from collections import Counter
from urllib.parse import unquote
import argparse

from request_parser import RequestParser, NormalizedRequest

LABEL_MAP = {
    0: "Normal",
    1: "SQL Injection",
    2: "XSS",
    3: "Command Injection",
    4: "Path Traversal / LFI",
    5: "Other Attack (SSTI/XXE/SSRF)",
}


def _locate_threats(req: NormalizedRequest) -> list:
    """Xác định vị trí xuất hiện các mẫu tấn công (Path, Query, Body, Headers)."""
    locations = []
    sql_p = r'(select|union|insert|drop|where|delete|--|/\*|\*/|xp_cmdshell|update|exec|waitfor)'
    js_p = r'(script|alert|onerror|onload|eval|javascript:|document\.cookie|iframe|<img|<svg)'
    cmd_p = r'(\bbash\b|\bcmd\b|\bping\b|\bwget\b|\bcurl\b|\bchmod\b|\bcat\b|/bin/sh|\bpowershell\b|\bwhoami\b|/etc/passwd)'
    path_p = r'(\.\./|\.\.\\|%2e%2e|/etc/passwd|boot\.ini|win\.ini)'
    modern_p = r'(\{\{|\{%|\$\{|\$gt|\$ne|<!doctype|<!entity|169\.254\.169\.254)'

    all_patterns = f"({sql_p}|{js_p}|{cmd_p}|{path_p}|{modern_p})"

    # 1. Kiểm tra Path
    if re.search(all_patterns, unquote(req.path).lower()):
        locations.append("URL Path")

    # 2. Kiểm tra Query parameters
    if req.query:
        query_text = " ".join(f"{k} {v}" for k, v in req.query.items())
        if re.search(all_patterns, unquote(query_text).lower()):
            locations.append("Query Parameter")

    # 3. Kiểm tra Body
    if req.body:
        if re.search(all_patterns, unquote(req.body).lower()):
            locations.append("Request Body")

    # 4. Kiểm tra Headers
    if req.headers:
        for hk, hv in req.headers.items():
            if hk in ("user-agent", "cookie", "referer", "x-forwarded-for"):
                if re.search(all_patterns, unquote(str(hv)).lower()):
                    locations.append(f"Header ({hk})")

    return locations


def _build_evaluation_target(req: NormalizedRequest) -> str:
    """Xây dựng chuỗi đích từ các thành phần đã chuẩn hóa để Feature Extractor phân tích."""
    raw_path = req.path or req.url or "/"
    clean_path = re.sub(r'^https?://[^/]+', '', raw_path)
    clean_path = re.sub(r'\s+HTTP/\d\.\d\s*$', '', clean_path).strip()
    if not clean_path.startswith('/'):
        clean_path = '/' + clean_path

    query_str = ""
    if "?" in clean_path:
        clean_path, existing_q = clean_path.split("?", 1)
        query_str = existing_q

    if req.query:
        if isinstance(req.query, dict):
            extra_q = "&".join(f"{k}={v}" for k, v in req.query.items() if f"{k}=" not in query_str)
        else:
            extra_q = str(req.query)
        if extra_q:
            query_str = f"{query_str}&{extra_q}" if query_str else extra_q

    is_form = (
        req.content_type == "application/x-www-form-urlencoded" or
        ("=" in req.body and not req.body.strip().startswith(("{", "[", "<")))
    )

    if req.body and is_form:
        body_clean = req.body.strip()
        query_str = f"{query_str}&{body_clean}" if query_str else body_clean

    target_url = f"{clean_path}?{query_str}" if query_str else clean_path

    if req.body and not is_form:
        target_url = f"{target_url} {req.body.strip()}"

    if req.headers and isinstance(req.headers, dict):
        for hk in ("user-agent", "cookie", "referer", "x-forwarded-for"):
            h_val = req.headers.get(hk, "")
            if h_val and h_val != "-":
                if re.search(r'(\.\./|<script|union\s|select\s|/bin/sh|/etc/passwd|\$\{|\{\{)', h_val, re.IGNORECASE):
                    target_url = f"{target_url} {h_val}"

    return target_url


def extract_features(request_or_url) -> dict:
    """Trích xuất 30 đặc trưng từ NormalizedRequest hoặc chuỗi URL/payload."""
    if isinstance(request_or_url, NormalizedRequest):
        req = request_or_url
    elif isinstance(request_or_url, dict) and "input_type" in request_or_url:
        req = NormalizedRequest(**request_or_url)
    elif isinstance(request_or_url, str):
        req = RequestParser.parse(request_or_url)
    else:
        req = NormalizedRequest(url=str(request_or_url))

    original_url = _build_evaluation_target(req)
    url_decoded = unquote(original_url).lower()

    # Regex patterns cho các nhóm tấn công
    sql_words = r'(select|union|insert|drop|where|delete|and\s|or\s|--|/\*|\*/|xp_cmdshell|update|exec|waitfor|concat|group_by|order\sby|having|information_schema|load_file|into\soutfile|benchmark|sleep|extractvalue|updatexml)'
    js_words = r'(script|alert|onerror|onload|eval|javascript:|document\.cookie|iframe|src=|img|prompt|confirm|onfocus|onmouseover|fromcharcode)'
    cmd_words = r'(\bbash\b|\bcmd\b|\bping\b|\bwget\b|\bcurl\b|\bchmod\b|\bcat\b|/bin/sh|\bpowershell\b|\bnslookup\b|nc\s|\bnetcat\b|\bwhoami\b|\bls\b|\bid\b|/etc/passwd|/etc/shadow|sleep\s|system\()'
    path_pattern = r'(\.\.\/|\.\.\\|\%2e\%2e|\%2f|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|php://|file://|data://|expect://|proc/self)'
    nosql_pattern = r'(\$gt|\$ne|\$lt|\$gte|\$lte|\$regex|\$where|\$exists|\$nin|\$or|\$and)'
    ssti_pattern = r'(\{\{|\{%|\$\{|<%=|#\{|__class__|__mro__|__subclasses__|__globals__|__builtins__)'
    xxe_pattern = r'(<!doctype|<!entity|system\s|<!--|<\?xml|cdata\[|xmlns)'
    ssrf_pattern = r'(127\.0\.0\.1|169\.254\.169\.254|0x7f|localhost|::1|metadata\.google|0177\.0\.0\.1|2130706433|gopher://|dict://)'

    length = len(url_decoded)
    special_char_count = len(re.findall(r'[!@#$%^&*()\":{}<>]', url_decoded))

    features = {
        # ── 14 features gốc ──
        'length': length,
        'special_char_count': special_char_count,
        'sql_keywords': len(re.findall(sql_words, url_decoded)),
        'js_keywords': len(re.findall(js_words, url_decoded)),
        'cmd_keywords': len(re.findall(cmd_words, url_decoded)),
        'path_traversal': len(re.findall(path_pattern, url_decoded)),
        'single_quotes': url_decoded.count("'"),
        'percent_encoding': url_decoded.count('%'),
        'is_brute': 1 if ('login' in url_decoded and 'password' in url_decoded and ('admin' in url_decoded or "'" in url_decoded)) else 0,
        'num_digits': sum(c.isdigit() for c in url_decoded),
        'num_params': url_decoded.count('&'),
        'has_encoded': 1 if '%' in url_decoded else 0,
        'has_path_traversal': 1 if '../' in url_decoded else 0,
        'has_admin': 1 if 'admin' in url_decoded else 0,
    }

    # ── 9 features bổ sung v1 ──
    char_freq = Counter(url_decoded)
    n = len(url_decoded) or 1
    entropy = -sum((c / n) * math.log2(c / n) for c in char_freq.values())
    features['entropy'] = round(entropy, 4)
    features['special_ratio'] = round(special_char_count / n, 4)

    parts = url_decoded.split('?', 1)
    features['path_length'] = len(parts[0])
    features['query_length'] = len(parts[1]) if len(parts) > 1 else 0
    features['path_depth'] = url_decoded.count('/')
    features['uppercase_ratio'] = round(
        sum(1 for c in original_url if c.isupper()) / max(len(original_url), 1), 4
    )
    params = url_decoded.split('&')
    features['avg_param_length'] = round(sum(len(p) for p in params) / max(len(params), 1), 2)
    features['double_encoded'] = 1 if '%25' in url_decoded else 0
    features['has_null_byte'] = 1 if '%00' in original_url else 0

    # ── 7 features hiện đại mới v2 ──
    features['nosql_keywords'] = len(re.findall(nosql_pattern, url_decoded))
    features['ssti_patterns'] = len(re.findall(ssti_pattern, url_decoded))
    features['xxe_patterns'] = len(re.findall(xxe_pattern, url_decoded))
    features['ssrf_patterns'] = len(re.findall(ssrf_pattern, url_decoded))
    features['has_unicode_escape'] = 1 if re.search(r'(%u[0-9a-f]{4}|\\u[0-9a-f]{4})', url_decoded) else 0

    if '?' in url_decoded:
        query = url_decoded.split('?', 1)[1]
        param_parts = query.split('&')
        param_vals = [p.split('=', 1)[1] if '=' in p else p for p in param_parts]
        features['max_param_length'] = max(len(v) for v in param_vals) if param_vals else 0
    else:
        features['max_param_length'] = 0

    features['non_ascii_count'] = sum(1 for c in url_decoded if ord(c) > 127)

    return features


def _is_clean_benign_request(req: NormalizedRequest, feat: dict) -> bool:
    """Kiểm tra xem request có phải là request thông thường hoàn toàn lành tính không có dấu vết tấn công."""
    # 1. Có bất kỳ pattern tấn công nào được kích hoạt không?
    has_threat = (
        feat.get('sql_keywords', 0) > 0 or
        feat.get('js_keywords', 0) > 0 or
        feat.get('cmd_keywords', 0) > 0 or
        feat.get('path_traversal', 0) > 0 or
        feat.get('nosql_keywords', 0) > 0 or
        feat.get('ssti_patterns', 0) > 0 or
        feat.get('xxe_patterns', 0) > 0 or
        feat.get('ssrf_patterns', 0) > 0 or
        feat.get('single_quotes', 0) > 0 or
        feat.get('has_null_byte', 0) > 0 or
        feat.get('double_encoded', 0) > 0 or
        feat.get('has_unicode_escape', 0) > 0 or
        feat.get('has_path_traversal', 0) > 0 or
        feat.get('is_brute', 0) > 0
    )
    if has_threat:
        return False

    # 2. Kiểm tra các mục tiêu nhạy cảm hoặc backdoor/probe
    clean_path = (req.path or "/").strip().lower()
    sensitive_probes = (
        ".env", ".git", ".htaccess", "wp-login", "wp-admin", "phpmyadmin",
        "/admin", "/passwd", "/shadow", "web.config", "/cgi-bin", "eval(",
        "cmd.exe", "powershell", "/root", "/bin"
    )
    if any(p in clean_path for p in sensitive_probes):
        return False

    # 3. Request tĩnh thông thường không chứa tham số hoặc body độc hại
    if not req.query and not req.body:
        if re.match(r'^/[a-zA-Z0-9_\-\./]*$', clean_path):
            return True

    # 4. Request form hoặc query thông thường lành tính
    if not has_threat and feat.get('special_char_count', 0) <= 6:
        if not feat.get('has_admin', 0):
            return True

    return False


class WebAttackDetector:
    """Bộ nhận diện và phân loại tấn công web (Multi-class và Binary)."""

    def __init__(self, model_path: str = None, feature_names_path: str = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))

        # Tự động chọn model tốt nhất có sẵn
        if model_path is None:
            multiclass_model = os.path.join(base_dir, "models", "best_model_multiclass.pkl")
            rf_model = os.path.join(base_dir, "models", "best_model_random_forest.pkl")
            if os.path.exists(multiclass_model):
                model_path = multiclass_model
            elif os.path.exists(rf_model):
                model_path = rf_model
            else:
                raise FileNotFoundError("Không tìm thấy model nào trong thư mục models/")
        elif not os.path.isabs(model_path):
            if os.path.exists(model_path):
                model_path = os.path.abspath(model_path)
            else:
                model_path = os.path.join(base_dir, model_path)

        if feature_names_path is None:
            feature_names_path = os.path.join(base_dir, "models", "feature_names.pkl")
        elif not os.path.isabs(feature_names_path):
            if os.path.exists(feature_names_path):
                feature_names_path = os.path.abspath(feature_names_path)
            else:
                feature_names_path = os.path.join(base_dir, feature_names_path)

        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Không tìm thấy file model: {model_path}")
        if not os.path.exists(feature_names_path):
            raise FileNotFoundError(f"Không tìm thấy file feature names: {feature_names_path}")

        self.model = joblib.load(model_path)
        self.feature_names = joblib.load(feature_names_path)

        # Label map
        label_map_file = os.path.join(base_dir, "models", "label_map.pkl")
        if os.path.exists(label_map_file):
            self.label_map = joblib.load(label_map_file)
        else:
            self.label_map = LABEL_MAP

        # Kiểm tra chế độ (Multi-class hay Binary)
        if hasattr(self.model, "classes_") and len(self.model.classes_) > 2:
            self.is_multiclass = True
            self.classes_ = list(self.model.classes_)
        else:
            self.is_multiclass = False
            self.classes_ = [0, 1]

    def _prepare_df(self, feat_dicts: list) -> pd.DataFrame:
        df = pd.DataFrame(feat_dicts)
        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0
        return df[self.feature_names]

    def predict_request(self, request_or_raw, threshold: float = 0.35, input_type: str = "auto") -> dict:
        """Phân tích và dự đoán từ bất kỳ định dạng request nào (URL, HTTP, cURL, Log)."""
        if isinstance(request_or_raw, NormalizedRequest):
            req = request_or_raw
        elif isinstance(request_or_raw, dict) and "input_type" in request_or_raw:
            req = NormalizedRequest(**request_or_raw)
        else:
            req = RequestParser.parse(str(request_or_raw), input_type=input_type)

        feat = extract_features(req)
        df_feat = self._prepare_df([feat])

        class_probs = {}
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(df_feat)[0]
            for cls_idx, p in zip(self.classes_, probs):
                class_name = self.label_map.get(int(cls_idx), f"Class {cls_idx}")
                class_probs[class_name] = round(float(p), 4)

            prob_normal = float(probs[0]) if 0 in self.classes_ else float(1.0 - probs[1])
            prob_attack = round(float(1.0 - prob_normal), 4)
            is_attack = prob_attack > threshold

            if is_attack:
                if _is_clean_benign_request(req, feat):
                    is_attack = False
                    prob_attack = round(min(prob_attack, 0.05), 4)
                    pred_label_id = 0
                    attack_type = "Normal"
                else:
                    attack_indices = [i for i, c in enumerate(self.classes_) if c != 0]
                    best_attack_idx = attack_indices[int(np.argmax(probs[attack_indices]))]
                    pred_label_id = int(self.classes_[best_attack_idx])
                    attack_type = self.label_map.get(pred_label_id, "Malicious Request")
            else:
                pred_label_id = 0
                attack_type = "Normal"
        else:
            pred = int(self.model.predict(df_feat)[0])
            is_attack = pred != 0
            prob_attack = 1.0 if is_attack else 0.0
            pred_label_id = pred
            attack_type = self.label_map.get(pred, "Attack" if is_attack else "Normal")

        # Xác định vị trí mối đe dọa (URL Path, Query, Body, Headers)
        threat_locations = _locate_threats(req) if is_attack else []

        return {
            "normalized_request": req.to_dict(),
            "url": req.url,
            "path": req.path,
            "method": req.method,
            "is_attack": bool(is_attack),
            "probability": prob_attack,
            "label": "Attack" if is_attack else "Normal",
            "attack_type": attack_type,
            "label_id": pred_label_id,
            "threat_locations": threat_locations,
            "class_probabilities": class_probs,
            "features": feat
        }

    def predict_url(self, url: str, threshold: float = 0.35) -> dict:
        """Dự đoán cho URL (tương thích ngược)."""
        return self.predict_request(url, threshold=threshold, input_type="url")

    def predict_batch(self, items: list, threshold: float = 0.35) -> list:
        """Dự đoán cho danh sách URL hoặc NormalizedRequest."""
        if not items:
            return []

        parsed_reqs = [
            item if isinstance(item, NormalizedRequest) else RequestParser.parse(str(item))
            for item in items
        ]
        feats = [extract_features(r) for r in parsed_reqs]
        df_feat = self._prepare_df(feats)

        results = []
        if hasattr(self.model, "predict_proba"):
            probs_matrix = self.model.predict_proba(df_feat)
            attack_indices = [i for i, c in enumerate(self.classes_) if c != 0]

            for req, probs, feat in zip(parsed_reqs, probs_matrix, feats):
                prob_normal = float(probs[0]) if 0 in self.classes_ else float(1.0 - probs[1])
                prob_attack = round(float(1.0 - prob_normal), 4)
                is_attack = prob_attack > threshold

                if is_attack:
                    if _is_clean_benign_request(req, feat):
                        is_attack = False
                        prob_attack = round(min(prob_attack, 0.05), 4)
                        pred_label_id = 0
                        attack_type = "Normal"
                    else:
                        best_attack_idx = attack_indices[int(np.argmax(probs[attack_indices]))]
                        pred_label_id = int(self.classes_[best_attack_idx])
                        attack_type = self.label_map.get(pred_label_id, "Malicious Request")
                else:
                    pred_label_id = 0
                    attack_type = "Normal"

                class_probs = {self.label_map.get(int(c), f"Class {c}"): round(float(p), 4)
                               for c, p in zip(self.classes_, probs)}

                threat_locations = _locate_threats(req) if is_attack else []

                results.append({
                    "normalized_request": req.to_dict(),
                    "url": req.url or req.path,
                    "method": req.method,
                    "is_attack": bool(is_attack),
                    "probability": prob_attack,
                    "label": "Attack" if is_attack else "Normal",
                    "attack_type": attack_type,
                    "label_id": pred_label_id,
                    "threat_locations": threat_locations,
                    "class_probabilities": class_probs,
                })
        else:
            preds = self.model.predict(df_feat)
            for req, pred, feat in zip(parsed_reqs, preds, feats):
                is_attack = pred != 0
                threat_locations = _locate_threats(req) if is_attack else []
                results.append({
                    "normalized_request": req.to_dict(),
                    "url": req.url or req.path,
                    "method": req.method,
                    "is_attack": bool(is_attack),
                    "probability": 1.0 if is_attack else 0.0,
                    "label": "Attack" if is_attack else "Normal",
                    "attack_type": self.label_map.get(int(pred), "Attack" if is_attack else "Normal"),
                    "label_id": int(pred),
                    "threat_locations": threat_locations,
                })

        return results

    def analyze_log_lines(self, lines: list, threshold: float = 0.35) -> dict:
        """Phân tích danh sách các dòng log thông qua RequestParser."""
        parsed_reqs = []
        for line in lines:
            line_str = str(line).strip()
            if not line_str:
                continue
            req = RequestParser.parse(line_str, input_type="auto")
            parsed_reqs.append(req)

        if not parsed_reqs:
            return {
                "total_requests": 0,
                "attack_count": 0,
                "normal_count": 0,
                "attack_rate": 0.0,
                "attack_breakdown": {},
                "details": []
            }

        results = self.predict_batch(parsed_reqs, threshold=threshold)
        attack_count = sum(1 for r in results if r["is_attack"])
        breakdown = Counter(r["attack_type"] for r in results if r["is_attack"])

        return {
            "total_requests": len(parsed_reqs),
            "attack_count": attack_count,
            "normal_count": len(parsed_reqs) - attack_count,
            "attack_rate": round((attack_count / len(parsed_reqs)) * 100, 2),
            "attack_breakdown": dict(breakdown),
            "details": results
        }

    def analyze_log(self, log_path: str, threshold: float = 0.35) -> dict:
        """Đọc và phân tích file log từ đường dẫn trên đĩa."""
        if not os.path.exists(log_path):
            raise FileNotFoundError(f"Không tìm thấy file log: {log_path}")

        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        return self.analyze_log_lines(lines, threshold=threshold)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Attack Detection CLI (Multi-Format & Multi-Class)")
    parser.add_argument("--url", type=str, help="Type 1: URL cần kiểm tra")
    parser.add_argument("--raw-http", type=str, help="Type 2: Raw HTTP request text")
    parser.add_argument("--curl", type=str, help="Type 3: cURL command string")
    parser.add_argument("--log", type=str, help="Type 4: Đường dẫn file log cần quét")
    parser.add_argument("--input", type=str, help="Auto-detect: URL, Raw HTTP, cURL, hoặc log line")
    parser.add_argument("--threshold", type=float, default=0.35, help="Ngưỡng phát hiện (mặc định: 0.35)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Chế độ nhập trực tiếp từ bàn phím")

    args = parser.parse_args()
    detector = WebAttackDetector()

    if args.interactive:
        print("\n" + "=" * 65)
        print("  CHE DO KIEM TRA TRUC TIEP (Ho tro: URL, Raw HTTP, cURL, Log)")
        print("  Go 'exit' de thoat.")
        print("=" * 65)
        while True:
            try:
                user_input = input("\nNhap request: ").strip()
                if not user_input:
                    continue
                if user_input.lower() in ("exit", "quit", "q"):
                    print("Tạm biệt!")
                    break
                res = detector.predict_request(user_input, threshold=args.threshold)
                norm = res["normalized_request"]
                tag = f"[ATTACK - {res['attack_type'].upper()}]" if res["is_attack"] else "[NORMAL - SAFE]"
                print(f"\nPhan tich cu phap ({norm['input_type'].upper()}):")
                print(f"  Method: {norm['method']} | Path: {norm['path']}")
                if norm['body']:
                    print(f"  Body: {norm['body']}")
                print(f"Ket qua danh gia: {tag} (Xac suat: {res['probability'] * 100:.1f}%)")
                if res["threat_locations"]:
                    print(f"Vi tri moi de doa: {', '.join(res['threat_locations'])}")
            except (KeyboardInterrupt, EOFError):
                break

    elif args.url or args.curl or args.raw_http or args.input:
        raw_val = args.url or args.curl or args.raw_http or args.input
        fmt = "url" if args.url else ("curl" if args.curl else ("raw_http" if args.raw_http else "auto"))
        res = detector.predict_request(raw_val, threshold=args.threshold, input_type=fmt)
        norm = res["normalized_request"]
        tag = f"[{res['attack_type'].upper()}]" if res["is_attack"] else "[NORMAL]"

        print("\n" + "=" * 60)
        print("  KET QUA CHUAN HOA (NORMALIZED REQUEST)")
        print("=" * 60)
        print(json.dumps(norm, indent=2, ensure_ascii=False))
        print("-" * 60)
        print(f"Ket qua danh gia: {tag} (Xac suat nguy co: {res['probability'] * 100:.1f}%)")
        if res["threat_locations"]:
            print(f"Vi tri phat hien: {', '.join(res['threat_locations'])}")
        print("=" * 60)

    elif args.log:
        print(f"\nDang quet file log: {args.log} ...")
        summary = detector.analyze_log(args.log, threshold=args.threshold)
        print(f"Tong so requests : {summary['total_requests']}")
        print(f"So attack        : {summary['attack_count']}")
        print(f"So normal        : {summary['normal_count']}")
        print(f"Ty le attack     : {summary['attack_rate']}%")
        print("Phan loai attack:")
        for atype, cnt in summary.get("attack_breakdown", {}).items():
            print(f"  - {atype:<30}: {cnt}")
        print()
    else:
        # Chạy test 4 định dạng mặc định
        print("=== Test 4 Dinh Dang Request Mau ===")
        test_samples = [
            ("Type 1: Raw URL", "https://example.com/search?q=<script>alert(1)</script>"),
            ("Type 2: Raw HTTP", "POST /api/login HTTP/1.1\nHost: target.com\nContent-Type: application/json\n\n{\"user\":\"admin' OR '1'='1\"}"),
            ("Type 3: cURL", 'curl -i -X POST http://TARGET/login -d "username=duy&password=DemoPass123"'),
            ("Type 4: Access Log", '192.168.1.1 - - [11/Nov/2026:12:00:00] "GET /view?file=../../../../etc/passwd HTTP/1.1" 200 452'),
        ]
        for name, sample in test_samples:
            res = detector.predict_request(sample)
            norm = res["normalized_request"]
            tag = f"[{res['attack_type'].upper()}]" if res["is_attack"] else "[NORMAL]"
            print(f"\n>> {name} ({norm['input_type']})")
            print(f"   Method: {norm['method']} | Path: {norm['path']}")
            if norm['body']:
                print(f"   Body: {norm['body']}")
            print(f"   Result: {tag:<30} (Prob: {res['probability']*100:5.1f}%)")
