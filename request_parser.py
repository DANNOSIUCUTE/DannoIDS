"""
request_parser.py - Unified Multi-Format HTTP Request Parser
Hỗ trợ 4 định dạng:
  Type 1 – Raw URL
  Type 2 – Raw HTTP Request
  Type 3 – cURL Command
  Type 4 – Access Log

ĐIỀU KIỆN QUAN TRỌNG:
  Parser không tự quyết định Normal hay Attack.
  Nhiệm vụ của parser CHỈ là phân tích và chuẩn hóa dữ liệu.
  Mọi định dạng đều trả về cùng một cấu trúc chuẩn (NormalizedRequest).
"""

import re
import shlex
from urllib.parse import urlsplit, parse_qs, unquote


class NormalizedRequest:
    """Cấu trúc chuẩn hóa cho mọi định dạng request."""

    def __init__(
        self,
        input_type: str = "url",
        method: str = "GET",
        url: str = "",
        path: str = "",
        query: dict = None,
        headers: dict = None,
        body: str = "",
        content_type: str = "",
        raw_input: str = "",
        extra: dict = None
    ):
        self.input_type = input_type
        self.method = (method or "GET").upper()
        self.url = url or ""
        self.path = path or ""
        self.query = query if query is not None else {}
        self.headers = headers if headers is not None else {}
        self.body = body or ""
        self.content_type = content_type or ""
        self.raw_input = raw_input or ""
        self.extra = extra if extra is not None else {}

    def to_dict(self) -> dict:
        return {
            "input_type": self.input_type,
            "method": self.method,
            "url": self.url,
            "path": self.path,
            "query": self.query,
            "headers": self.headers,
            "body": self.body,
            "content_type": self.content_type,
        }

    def __repr__(self) -> str:
        return (
            f"<NormalizedRequest type={self.input_type} method={self.method} "
            f"path='{self.path}' body_len={len(self.body)}>"
        )


class RequestParser:
    """Parser chuẩn hóa mọi định dạng request web thành NormalizedRequest."""

    @staticmethod
    def detect_format(raw: str) -> str:
        """Tự động nhận diện định dạng input (url, raw_http, curl, log)."""
        s = raw.strip()
        if not s:
            return "url"

        # 1. cURL command (kể cả khi nằm trong bash wrapper/loop)
        if re.search(r'\b(?:sudo\s+)?curl\b', s, re.IGNORECASE):
            return "curl"

        # 2. Raw HTTP Request (bắt đầu bằng METHOD /path HTTP/1.x hoặc 2)
        first_line = s.splitlines()[0].strip()
        if re.match(r'^(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP/\d', first_line, re.IGNORECASE):
            return "raw_http"

        # 3. Access Log: Chứa IP, timestamp, và "METHOD /path HTTP/1.x"
        if re.search(r'^\S+\s+\S+\s+\S+\s+\[.*?\]\s+\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)', s, re.IGNORECASE):
            return "log"
        if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*\"(?:GET|POST|PUT|DELETE)', s):
            return "log"
        if re.search(r',/[^,]+\s+HTTP/1\.[01]', s):
            return "log"

        # 4. Mặc định là URL
        return "url"

    @classmethod
    def parse(cls, raw: str, input_type: str = "auto") -> NormalizedRequest:
        """Parse input thành NormalizedRequest.
        
        Args:
            raw: Chuỗi request đầu vào
            input_type: "auto" | "url" | "raw_http" | "curl" | "log"
        """
        raw_clean = raw.strip()
        if not raw_clean:
            return NormalizedRequest(input_type="url", raw_input=raw)

        if input_type == "auto":
            input_type = cls.detect_format(raw_clean)

        if input_type == "curl":
            return cls.parse_curl(raw_clean)
        elif input_type == "raw_http":
            return cls.parse_raw_http(raw_clean)
        elif input_type == "log":
            return cls.parse_log_line(raw_clean)
        else:
            return cls.parse_url(raw_clean)

    # ══════════════════════════════════════════════════════════════
    #  TYPE 1: RAW URL
    # ══════════════════════════════════════════════════════════════
    @classmethod
    def parse_url(cls, raw_url: str) -> NormalizedRequest:
        url_clean = raw_url.strip()
        # Bỏ HTTP/1.1 suffix nếu có
        url_clean = re.sub(r'\s+HTTP/\d\.\d\s*$', '', url_clean).strip()

        # Đảm bảo URL có thể parse được bởi urlsplit
        target = url_clean
        if not target.startswith(("http://", "https://", "/")):
            target = "http://" + target

        parsed = urlsplit(target)
        path = parsed.path if parsed.path else "/"
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        # Chuyển list 1 phần tử thành string đơn giản nếu cần
        flat_query = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}

        return NormalizedRequest(
            input_type="url",
            method="GET",
            url=url_clean,
            path=path,
            query=flat_query,
            headers={},
            body="",
            content_type="",
            raw_input=raw_url
        )

    # ══════════════════════════════════════════════════════════════
    #  TYPE 2: RAW HTTP REQUEST
    # ══════════════════════════════════════════════════════════════
    @classmethod
    def parse_raw_http(cls, raw_http: str) -> NormalizedRequest:
        # Chuẩn hóa xuống dòng
        text = raw_http.replace("\r\n", "\n").replace("\r", "\n")
        parts = text.split("\n\n", 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ""

        lines = header_section.split("\n")
        first_line = lines[0].strip() if lines else ""

        # Parse request line: METHOD PATH HTTP/VERSION
        req_line_match = re.match(r'^([A-Za-z]+)\s+(\S+)(?:\s+HTTP/\d\.\d)?', first_line)
        if req_line_match:
            method = req_line_match.group(1).upper()
            raw_path = req_line_match.group(2)
        else:
            method = "GET"
            raw_path = "/"

        # Parse headers
        headers = {}
        content_type = ""
        host = ""
        for line in lines[1:]:
            line_str = line.strip()
            if not line_str or ":" not in line_str:
                continue
            k, v = line_str.split(":", 1)
            key = k.strip().lower()
            val = v.strip()
            headers[key] = val
            if key == "content-type":
                content_type = val.split(";")[0].strip()
            elif key == "host":
                host = val

        # Xây dựng full URL
        parsed = urlsplit(raw_path)
        path = parsed.path if parsed.path else "/"
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        flat_query = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}

        if raw_path.startswith(("http://", "https://")):
            full_url = raw_path
        elif host:
            full_url = f"http://{host}{raw_path}"
        else:
            full_url = raw_path

        return NormalizedRequest(
            input_type="raw_http",
            method=method,
            url=full_url,
            path=path,
            query=flat_query,
            headers=headers,
            body=body,
            content_type=content_type,
            raw_input=raw_http
        )

    # ══════════════════════════════════════════════════════════════
    #  TYPE 3: cURL COMMAND
    # ══════════════════════════════════════════════════════════════
    @classmethod
    def parse_curl(cls, curl_cmd: str) -> NormalizedRequest:
        # 1. Trích xuất phần lệnh curl nếu nằm trong vòng lặp bash hoặc script
        m_curl = re.search(r'\b(?:sudo\s+)?curl\b.*', curl_cmd, re.DOTALL)
        cmd_text = m_curl.group(0) if m_curl else curl_cmd

        # 2. Xóa bỏ ký tự `\` nối dòng (dù có newline hay chỉ có khoảng trắng theo sau)
        cleaned = re.sub(r'\\\s*', ' ', cmd_text).strip()

        # 3. Tokenize bằng shlex (an toàn, không execute command)
        try:
            tokens = shlex.split(cleaned)
        except Exception:
            tokens = cleaned.split()

        method = None
        url = ""
        headers = {}
        body_parts = []
        content_type = ""
        is_get = False

        # Flags có 1 tham số đi kèm
        flags_with_arg = {
            "-X", "--request", "-H", "--header", "-d", "--data", "--data-raw",
            "--data-binary", "--data-ascii", "--data-urlencode", "--url",
            "-o", "--output", "-u", "--user", "-A", "--user-agent", "-e", "--referer",
            "-b", "--cookie", "-c", "--cookie-jar", "-m", "--max-time"
        }

        # Flags boolean không có tham số
        boolean_flags = {
            "-i", "--include", "-I", "--head", "-s", "--silent", "-S", "--show-error",
            "-k", "--insecure", "-v", "--verbose", "-L", "--location", "-G", "--get",
            "--path-as-is", "--compressed", "-N", "--no-buffer"
        }

        i = 0
        while i < len(tokens):
            token = tokens[i]

            # Bỏ qua curl/sudo
            if token.lower() in ("curl", "sudo"):
                i += 1
                continue

            # Method (-X, --request)
            if token in ("-X", "--request") and i + 1 < len(tokens):
                method = tokens[i + 1].upper()
                i += 2
                continue

            # --get / -G flag
            if token in ("-G", "--get"):
                is_get = True
                i += 1
                continue

            # Headers (-H, --header)
            if token in ("-H", "--header") and i + 1 < len(tokens):
                h_val = tokens[i + 1]
                if ":" in h_val:
                    hk, hv = h_val.split(":", 1)
                    k = hk.strip().lower()
                    v = hv.strip()
                    headers[k] = v
                    if k == "content-type":
                        content_type = v.split(";")[0].strip()
                i += 2
                continue

            # User-Agent (-A)
            if token in ("-A", "--user-agent") and i + 1 < len(tokens):
                headers["user-agent"] = tokens[i + 1]
                i += 2
                continue

            # Cookie (-b)
            if token in ("-b", "--cookie") and i + 1 < len(tokens):
                headers["cookie"] = tokens[i + 1]
                i += 2
                continue

            # Referer (-e)
            if token in ("-e", "--referer") and i + 1 < len(tokens):
                headers["referer"] = tokens[i + 1]
                i += 2
                continue

            # Body / Data (-d, --data, --data-raw, --data-binary, --data-ascii, --data-urlencode)
            if token in ("-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode") and i + 1 < len(tokens):
                body_parts.append(tokens[i + 1])
                i += 2
                continue
            if token.startswith("-d") and len(token) > 2 and token not in flags_with_arg:
                body_parts.append(token[2:].strip("\"'"))
                i += 1
                continue

            # URL flag (--url)
            if token == "--url" and i + 1 < len(tokens):
                url = tokens[i + 1]
                i += 2
                continue

            # Boolean flags
            if token in boolean_flags:
                i += 1
                continue

            # Other flags with arg (e.g., -o /dev/null)
            if token in flags_with_arg and i + 1 < len(tokens):
                i += 2
                continue

            # URL positional argument (không bắt đầu bằng dấu -)
            if not token.startswith("-") and not url:
                url = token
                i += 1
                continue

            i += 1

        body = "&".join(body_parts) if body_parts else ""

        if is_get:
            method = "GET"
        elif not method:
            method = "POST" if body else "GET"

        # Chuẩn hóa URL & Path
        if not url:
            url = "/"
        parsed = urlsplit(url if "://" in url or url.startswith("/") else f"http://{url}")
        path = parsed.path if parsed.path else "/"
        query_dict = parse_qs(parsed.query, keep_blank_values=True)

        if is_get and body:
            # data được cURL đưa vào URL query params
            body_qs = parse_qs(body, keep_blank_values=True)
            for k, v in body_qs.items():
                if k in query_dict:
                    query_dict[k].extend(v)
                else:
                    query_dict[k] = v
            body = ""

        flat_query = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}

        # Content-Type mặc định
        if not content_type and body:
            s_body = body.strip()
            if s_body.startswith(("{", "[")):
                content_type = "application/json"
            else:
                content_type = "application/x-www-form-urlencoded"

        return NormalizedRequest(
            input_type="curl",
            method=method,
            url=url,
            path=path,
            query=flat_query,
            headers=headers,
            body=body,
            content_type=content_type,
            raw_input=curl_cmd
        )

    # ══════════════════════════════════════════════════════════════
    #  TYPE 4: ACCESS LOG
    # ══════════════════════════════════════════════════════════════
    @classmethod
    def parse_log_line(cls, line: str) -> NormalizedRequest:
        s = line.strip()

        # 1. Định dạng Web server: "METHOD /path HTTP/1.x"
        m = re.search(r'\"([A-Za-z]+)\s+(.*?)\s+HTTP/[0-9.]+\"', s)
        if m:
            method = m.group(1).upper()
            raw_path = m.group(2).strip()
        else:
            # 2. Định dạng CSV/testlog: ,/path HTTP/1.x
            m2 = re.search(r',([^,\"\']+)\s+HTTP/1\.[01]', s)
            if m2:
                method = "GET"
                raw_path = m2.group(1).strip()
            else:
                # 3. Dòng thô: lấy method nếu có ở đầu
                m3 = re.match(r'^([A-Za-z]+)\s+(\S+)', s)
                if m3 and m3.group(1).upper() in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
                    method = m3.group(1).upper()
                    raw_path = m3.group(2)
                else:
                    method = "GET"
                    raw_path = s

        # Tách IP nếu có ở đầu dòng
        ip_match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', s)
        client_ip = ip_match.group(1) if ip_match else ""

        # Tách Status code nếu có
        status_match = re.search(r'\"\s+(\d{3})\s+', s)
        status_code = status_match.group(1) if status_match else ""

        # Tách User-Agent nếu có (cột cuối thường trong ngoặc kép thứ 2)
        quoted_strings = re.findall(r'\"([^\"]*)\"', s)
        user_agent = quoted_strings[-1] if len(quoted_strings) >= 2 else ""

        headers = {}
        if client_ip:
            headers["client-ip"] = client_ip
        if user_agent and user_agent != "-":
            headers["user-agent"] = user_agent

        # Xóa prefix host
        clean_path = re.sub(r'^https?://[^/]+', '', raw_path)
        clean_path = re.sub(r'\s+HTTP/\d\.\d\s*$', '', clean_path).strip()
        if not clean_path:
            clean_path = "/"

        parsed = urlsplit(clean_path if clean_path.startswith("/") else "/" + clean_path)
        path = parsed.path if parsed.path else "/"
        query_dict = parse_qs(parsed.query, keep_blank_values=True)
        flat_query = {k: v[0] if len(v) == 1 else v for k, v in query_dict.items()}

        extra = {}
        if status_code:
            extra["status_code"] = status_code

        return NormalizedRequest(
            input_type="log",
            method=method,
            url=clean_path,
            path=path,
            query=flat_query,
            headers=headers,
            body="",
            content_type="",
            raw_input=line,
            extra=extra
        )

