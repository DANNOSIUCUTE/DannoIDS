"""
web_app.py - Web Attack Detection Dashboard (Pure Minimalist B&W Edition)
Font: Montserrat
Theme: Pure Black & White (#000000 background, crisp #ffffff text)
Architecture: Unified RequestParser -> 30 Features Extractor -> LightGBM Multi-Class

Chạy: python web_app.py
Truy cập: http://localhost:5000
"""

import os
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from detector import WebAttackDetector, extract_features
from request_parser import RequestParser

detector = WebAttackDetector()

HTML_PAGE = r"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Attack Detection Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-body: #000000;
            --bg-header: #000000;
            --bg-card: #080808;
            --bg-input: #000000;
            --bg-hover: #121212;
            --border: #222222;
            --border-light: #333333;
            --accent: #ffffff;
            --accent-dim: rgba(255, 255, 255, 0.08);
            --danger: #ef4444;
            --danger-dim: rgba(239, 68, 68, 0.12);
            --danger-border: rgba(239, 68, 68, 0.35);
            --success: #10b981;
            --success-dim: rgba(16, 185, 129, 0.12);
            --success-border: rgba(16, 185, 129, 0.35);
            --text-1: #ffffff;
            --text-2: #a3a3a3;
            --text-3: #666666;
            --mono: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            --sans: 'Montserrat', sans-serif;
            --radius: 6px;
        }

        *, *::before, *::after {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: var(--sans);
            background: var(--bg-body);
            color: var(--text-1);
            min-height: 100vh;
            -webkit-font-smoothing: antialiased;
            letter-spacing: -0.2px;
        }

        /* ── Header ───────────────────────────────────────── */
        .header {
            background: var(--bg-header);
            border-bottom: 1px solid var(--border);
        }
        .header-inner {
            max-width: 1100px;
            margin: 0 auto;
            padding: 20px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .brand h1 {
            font-size: 15px;
            font-weight: 700;
            color: var(--text-1);
            letter-spacing: 1px;
            text-transform: uppercase;
        }
        .header-right {
            display: flex;
            align-items: center;
            gap: 16px;
            font-size: 11px;
            font-weight: 600;
            color: var(--text-3);
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        .status-badge {
            background: #111111;
            border: 1px solid #333333;
            color: #ffffff;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 700;
        }

        /* ── Layout ───────────────────────────────────────── */
        .main {
            max-width: 1100px;
            margin: 0 auto;
            padding: 28px 24px 80px;
        }

        /* ── Tabs ─────────────────────────────────────────── */
        .tabs {
            display: flex;
            gap: 0;
            margin-bottom: 24px;
            border-bottom: 1px solid var(--border);
        }
        .tab {
            background: none;
            border: none;
            color: var(--text-3);
            font-family: var(--sans);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            padding: 12px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
            transition: all 0.15s ease;
        }
        .tab:hover {
            color: var(--text-2);
        }
        .tab.active {
            color: #ffffff;
            border-bottom-color: #ffffff;
        }

        /* ── Card ─────────────────────────────────────────── */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: var(--radius);
        }
        .card-body {
            padding: 26px;
        }

        /* ── Format Selector ──────────────────────────────── */
        .format-selector {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-bottom: 16px;
        }
        .fmt-btn {
            background: #000000;
            border: 1px solid var(--border);
            color: var(--text-3);
            font-family: var(--sans);
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.6px;
            text-transform: uppercase;
            padding: 7px 14px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.15s;
        }
        .fmt-btn:hover {
            color: var(--text-1);
            border-color: var(--border-light);
        }
        .fmt-btn.active {
            background: #ffffff;
            border-color: #ffffff;
            color: #000000;
            font-weight: 700;
        }

        /* ── Form Fields ──────────────────────────────────── */
        .field {
            margin-bottom: 20px;
        }
        .field-label {
            display: block;
            font-size: 11px;
            font-weight: 700;
            color: var(--text-3);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 8px;
        }
        .field-input {
            width: 100%;
            background: var(--bg-input);
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 14px 16px;
            color: var(--text-1);
            font-size: 13px;
            font-family: var(--mono);
            outline: none;
            transition: border-color 0.15s, box-shadow 0.15s;
            line-height: 1.6;
            resize: vertical;
        }
        .field-input:focus {
            border-color: #ffffff;
            box-shadow: 0 0 0 2px rgba(255, 255, 255, 0.15);
        }
        .field-input::placeholder {
            color: #444444;
        }
        select.field-input {
            font-family: var(--sans);
            font-size: 12px;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }

        /* ── Buttons ──────────────────────────────────────── */
        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            border: none;
            border-radius: 4px;
            font-family: var(--sans);
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            cursor: pointer;
            padding: 10px 22px;
            transition: all 0.15s;
        }
        .btn-primary {
            background: #ffffff;
            color: #000000;
        }
        .btn-primary:hover {
            background: #e5e5e5;
        }
        .btn-secondary {
            background: #000000;
            color: var(--text-1);
            border: 1px solid var(--border);
        }
        .btn-secondary:hover {
            border-color: #ffffff;
            background: #0a0a0a;
        }
        .btn-sm {
            padding: 5px 12px;
            font-size: 10px;
        }
        .btn:disabled {
            opacity: 0.35;
            cursor: not-allowed;
        }

        /* ── Quick Samples ────────────────────────────────── */
        .samples-group {
            margin-bottom: 12px;
        }
        .samples-title {
            font-size: 10px;
            font-weight: 700;
            color: var(--text-3);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-bottom: 6px;
        }
        .samples {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }
        .chip {
            background: #000000;
            color: var(--text-2);
            border: 1px solid var(--border);
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
            font-family: var(--sans);
            cursor: pointer;
            transition: all 0.15s;
        }
        .chip:hover {
            color: #ffffff;
            border-color: #ffffff;
            background: #0f0f0f;
        }
        .chip.chip-atk {
            border-left: 2px solid var(--danger);
        }
        .chip.chip-safe {
            border-left: 2px solid var(--success);
        }

        /* ── Spinner ──────────────────────────────────────── */
        @keyframes spin { to { transform: rotate(360deg); } }
        .spinner {
            display: none;
            align-items: center;
            gap: 10px;
            margin-top: 18px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.6px;
            text-transform: uppercase;
            color: var(--text-3);
        }
        .spinner.on { display: flex; }
        .spinner::before {
            content: '';
            width: 12px;
            height: 12px;
            border: 2px solid #333333;
            border-top-color: #ffffff;
            border-radius: 50%;
            animation: spin 0.6s linear infinite;
        }

        /* ── Results Container ────────────────────────────── */
        .results-container {
            display: none;
            margin-top: 30px;
            animation: fadeIn 0.25s ease;
        }
        .results-container.show { display: block; }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* ── Section Title ────────────────────────────────── */
        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border);
        }
        .section-title {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-2);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .step-badge {
            background: #ffffff;
            color: #000000;
            padding: 2px 7px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 800;
        }

        /* ── Stage 1: Normalized Request Panel ────────────── */
        .norm-panel {
            background: #000000;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px;
            margin-bottom: 28px;
        }
        .norm-meta-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
            margin-bottom: 14px;
            padding-bottom: 12px;
            border-bottom: 1px solid #1a1a1a;
        }
        .badge-type {
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            padding: 4px 10px;
            border-radius: 3px;
            background: #111111;
            color: #ffffff;
            border: 1px solid #333333;
        }
        .badge-method {
            font-size: 11px;
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 3px;
            background: #111111;
            color: #ffffff;
            border: 1px solid #333333;
            font-family: var(--mono);
        }
        .norm-path-val {
            font-family: var(--mono);
            font-size: 12px;
            color: var(--text-2);
            word-break: break-all;
        }

        .norm-json-viewer {
            background: #000000;
            border: 1px solid #1a1a1a;
            border-radius: 4px;
            padding: 16px;
            font-family: var(--mono);
            font-size: 12px;
            color: #e5e5e5;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 240px;
            overflow-y: auto;
            line-height: 1.6;
        }

        /* ── Stage 2: Security Assessment Panel ───────────── */
        .result-box {
            border-radius: var(--radius);
            overflow: hidden;
            padding: 24px;
            background: #000000;
            border: 1px solid var(--border);
        }
        .result-box.is-attack {
            border-color: var(--danger);
            background: rgba(239, 68, 68, 0.04);
        }
        .result-box.is-normal {
            border-color: var(--success);
            background: rgba(16, 185, 129, 0.04);
        }

        .result-top {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            margin-bottom: 18px;
        }
        .result-tag {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 6px 14px;
            border-radius: 3px;
            display: inline-block;
        }
        .result-tag.attack {
            background: #991b1b;
            color: #ffffff;
        }
        .result-tag.normal {
            background: #166534;
            color: #ffffff;
        }
        .result-score {
            font-size: 40px;
            font-weight: 800;
            line-height: 1;
            font-variant-numeric: tabular-nums;
        }
        .result-score.attack { color: var(--danger); }
        .result-score.normal { color: var(--success); }
        .result-msg {
            font-size: 13px;
            color: var(--text-2);
            margin-top: 10px;
            line-height: 1.5;
        }

        .threat-locations-row {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 12px;
            align-items: center;
        }
        .threat-loc-label {
            font-size: 10px;
            font-weight: 700;
            color: var(--text-3);
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        .threat-loc-badge {
            font-size: 10px;
            font-weight: 700;
            padding: 3px 9px;
            border-radius: 3px;
            background: #1a0808;
            color: #fca5a5;
            border: 1px solid #7f1d1d;
            letter-spacing: 0.4px;
        }

        .progress-track {
            height: 4px;
            background: #1a1a1a;
            border-radius: 2px;
            overflow: hidden;
            margin: 18px 0;
        }
        .progress-fill {
            height: 100%;
            transition: width 0.4s ease;
        }
        .progress-fill.attack { background: var(--danger); }
        .progress-fill.normal { background: var(--success); }

        /* Multi-class probabilities grid */
        .class-prob-section {
            margin-top: 22px;
            padding-top: 18px;
            border-top: 1px solid #1a1a1a;
        }
        .class-prob-title {
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-3);
            margin-bottom: 12px;
        }
        .class-prob-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 8px;
        }
        .class-prob-card {
            background: #000000;
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 10px 12px;
        }
        .class-prob-name {
            font-size: 10px;
            font-weight: 600;
            color: var(--text-3);
            text-transform: uppercase;
            letter-spacing: 0.4px;
        }
        .class-prob-val {
            font-size: 14px;
            font-weight: 700;
            color: #ffffff;
            font-variant-numeric: tabular-nums;
            margin-top: 4px;
        }
        .class-prob-val.highlight {
            color: var(--danger);
        }

        /* Feature grid */
        .feat-title {
            font-size: 10px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-3);
            margin-top: 24px;
            margin-bottom: 10px;
        }
        .result-features {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 6px;
        }
        .feat-item {
            font-size: 11px;
            background: #000000;
            border: 1px solid #1a1a1a;
            padding: 6px 10px;
            border-radius: 3px;
            display: flex;
            justify-content: space-between;
        }
        .feat-name {
            color: var(--text-3);
            font-family: var(--mono);
            font-size: 10px;
        }
        .feat-val {
            color: var(--text-2);
            font-weight: 700;
            font-family: var(--mono);
            font-size: 11px;
        }
        .feat-val.hot {
            color: var(--danger);
        }

        /* ── Tab 2: Log File Scanner ──────────────────────── */
        .dropzone {
            border: 1px dashed var(--border-light);
            border-radius: var(--radius);
            padding: 36px 20px;
            text-align: center;
            background: #000000;
            cursor: pointer;
            transition: all 0.2s ease;
            margin-bottom: 18px;
        }
        .dropzone:hover, .dropzone.dragover {
            border-color: #ffffff;
            background: #0a0a0a;
        }
        .drop-title {
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.8px;
            text-transform: uppercase;
            color: #ffffff;
            margin-bottom: 6px;
        }
        .drop-hint {
            font-size: 11px;
            color: var(--text-3);
        }

        .file-loaded-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #000000;
            border: 1px solid #333333;
            border-radius: var(--radius);
            padding: 14px 18px;
            margin-bottom: 18px;
        }
        .file-info-col {
            display: flex;
            flex-direction: column;
            gap: 2px;
        }
        .file-name-text {
            font-size: 13px;
            font-weight: 700;
            color: #ffffff;
            font-family: var(--mono);
        }
        .file-meta-text {
            font-size: 11px;
            color: var(--text-3);
        }
        .btn-clear {
            background: none;
            border: none;
            color: var(--text-3);
            font-size: 18px;
            cursor: pointer;
            padding: 4px 8px;
            border-radius: 4px;
            line-height: 1;
        }
        .btn-clear:hover {
            color: #ffffff;
        }

        /* ── Tab 2: Stats ─────────────────────────────────── */
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin-top: 24px;
        }
        .stat {
            background: #000000;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            padding: 20px 16px;
            text-align: center;
        }
        .stat-num {
            font-size: 32px;
            font-weight: 800;
            line-height: 1.1;
            font-variant-numeric: tabular-nums;
            color: #ffffff;
        }
        .stat-num.c-red { color: var(--danger); }
        .stat-num.c-green { color: var(--success); }
        .stat-label {
            font-size: 10px;
            font-weight: 700;
            color: var(--text-3);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-top: 6px;
        }

        .breakdown-row {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 18px;
        }
        .breakdown-chip {
            background: #000000;
            border: 1px solid var(--border);
            padding: 6px 14px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .breakdown-count {
            font-weight: 800;
            color: #ffffff;
        }

        /* ── Table ────────────────────────────────────────── */
        .tbl-section {
            margin-top: 28px;
        }
        .tbl-header-bar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        .tbl-head {
            font-size: 11px;
            font-weight: 700;
            color: var(--text-3);
            text-transform: uppercase;
            letter-spacing: 0.8px;
        }
        .tbl-wrap {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid var(--border);
            border-radius: var(--radius);
            background: #000000;
        }
        .tbl-wrap::-webkit-scrollbar { width: 5px; }
        .tbl-wrap::-webkit-scrollbar-track { background: #000000; }
        .tbl-wrap::-webkit-scrollbar-thumb { background: #222222; }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        thead {
            background: #050505;
            position: sticky;
            top: 0;
            z-index: 1;
        }
        th {
            padding: 10px 14px;
            text-align: left;
            font-size: 10px;
            font-weight: 700;
            color: var(--text-3);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            border-bottom: 1px solid var(--border);
        }
        td {
            padding: 9px 14px;
            font-size: 12px;
            border-bottom: 1px solid #141414;
            vertical-align: middle;
        }
        tr:hover td {
            background: #0a0a0a;
        }

        .tag-sm {
            display: inline-block;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.4px;
            padding: 3px 8px;
            border-radius: 3px;
            text-transform: uppercase;
        }
        .tag-sm.sqli { background: #1a1300; color: #fbbf24; border: 1px solid #78350f; }
        .tag-sm.xss { background: #1a0815; color: #f472b6; border: 1px solid #831843; }
        .tag-sm.cmdi { background: #1a0808; color: #f87171; border: 1px solid #7f1d1d; }
        .tag-sm.lfi { background: #13081a; color: #c084fc; border: 1px solid #581c87; }
        .tag-sm.other { background: #08161a; color: #22d3ee; border: 1px solid #155e75; }
        .tag-sm.normal { background: #061a0e; color: #4ade80; border: 1px solid #14532d; }

        .td-url {
            font-family: var(--mono);
            font-size: 11px;
            color: var(--text-2);
            word-break: break-all;
        }
        .td-prob {
            font-weight: 700;
            font-variant-numeric: tabular-nums;
            font-family: var(--mono);
        }
        .td-prob.high { color: var(--danger); }
        .td-prob.low { color: var(--success); }

        /* ── Footer ───────────────────────────────────────── */
        .footer {
            max-width: 1100px;
            margin: 0 auto;
            padding: 24px 24px 0;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--text-3);
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
        }

        .hidden { display: none !important; }
        @media (max-width: 760px) {
            .header-right { display: none; }
            .stats { grid-template-columns: 1fr; }
            .result-features { grid-template-columns: repeat(2, 1fr); }
            .class-prob-grid { grid-template-columns: 1fr 1fr; }
        }
    </style>
</head>
<body>

<div class="header">
    <div class="header-inner">
        <div class="brand">
            <h1>Web Attack Detection &amp; Classification</h1>
        </div>
        <div class="header-right">
            <span>Unified Parser &middot; 30 Features &middot; LightGBM</span>
            <span class="status-badge">Ready</span>
        </div>
    </div>
</div>

<div class="main">
    <div class="tabs">
        <button class="tab active" data-tab="single">Request Inspection</button>
        <button class="tab" data-tab="log">Log Scanner</button>
    </div>

    <!-- ═══ Tab 1: Multi-Format Request Analysis ═══ -->
    <div id="tab-single">
        <div class="card">
            <div class="card-body">
                <!-- Format selector buttons -->
                <div class="field">
                    <label class="field-label">Select Input Format</label>
                    <div class="format-selector" id="formatSelector">
                        <button type="button" class="fmt-btn active" data-fmt="auto">Auto Detect</button>
                        <button type="button" class="fmt-btn" data-fmt="url">Type 1: Raw URL</button>
                        <button type="button" class="fmt-btn" data-fmt="raw_http">Type 2: Raw HTTP</button>
                        <button type="button" class="fmt-btn" data-fmt="curl">Type 3: cURL</button>
                        <button type="button" class="fmt-btn" data-fmt="log">Type 4: Access Log</button>
                    </div>
                </div>

                <!-- Input textarea -->
                <div class="field">
                    <label class="field-label" id="inputFieldLabel">Request Input (Paste URL, Raw HTTP, cURL Command, or Log Line)</label>
                    <textarea class="field-input" id="requestInput" rows="5"
                        placeholder="Paste URL, Raw HTTP request, cURL command, or access log line..."></textarea>
                </div>

                <!-- Quick Samples categorized by format -->
                <div class="field">
                    <label class="field-label">Quick Test Samples</label>
                    
                    <div class="samples-group">
                        <div class="samples-title">Type 3 &middot; cURL Command Samples (Static Parsing, No Execution)</div>
                        <div class="samples">
                            <span class="chip chip-safe" data-fmt="curl" data-val='curl -i -X POST http://TARGET/login \
  -d "username=duy&password=DemoPass123"'>cURL Login (Benign Normal)</span>
                            <span class="chip chip-atk" data-fmt="curl" data-val='curl -i -X POST http://TARGET/login \
  -d "username=admin&#39; OR &#39;1&#39;=&#39;1--&password=123"'>cURL SQLi in Body</span>
                            <span class="chip chip-atk" data-fmt="curl" data-val='curl -X GET "http://target.com/view?file=../../../../etc/passwd"'>cURL LFI Path Traversal</span>
                        </div>
                    </div>

                    <div class="samples-group" style="margin-top: 10px;">
                        <div class="samples-title">Type 2 &middot; Raw HTTP Request Samples</div>
                        <div class="samples">
                            <span class="chip chip-safe" data-fmt="raw_http" data-val="GET /api/v1/users/42 HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0">Raw HTTP GET User (Benign)</span>
                            <span class="chip chip-atk" data-fmt="raw_http" data-val="POST /api/auth HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=admin' OR 1=1--&password=pass">Raw HTTP POST SQLi</span>
                            <span class="chip chip-atk" data-fmt="raw_http" data-val="POST /api/exec HTTP/1.1
Host: target.com
Content-Type: application/json

{&quot;command&quot;: &quot;;cat /etc/passwd&quot;}">Raw HTTP JSON Cmdi</span>
                        </div>
                    </div>

                    <div class="samples-group" style="margin-top: 10px;">
                        <div class="samples-title">Type 1 &middot; Raw URL Samples</div>
                        <div class="samples">
                            <span class="chip chip-safe" data-fmt="url" data-val="https://example.com/products?page=2&sort=price">Clean Parameterized URL</span>
                            <span class="chip chip-atk" data-fmt="url" data-val="https://example.com/search?q=&lt;script&gt;alert(1)&lt;/script&gt;">XSS Payload in Query</span>
                            <span class="chip chip-atk" data-fmt="url" data-val="https://example.com/render?template={{7*7}}">SSTI Payload</span>
                        </div>
                    </div>

                    <div class="samples-group" style="margin-top: 10px;">
                        <div class="samples-title">Type 4 &middot; Access Log Samples</div>
                        <div class="samples">
                            <span class="chip chip-safe" data-fmt="log" data-val='192.168.1.10 - - [10/Nov/2026:10:00:00 +0700] &quot;GET /index.html HTTP/1.1&quot; 200 452'>Benign Static Request Log</span>
                            <span class="chip chip-atk" data-fmt="log" data-val='192.168.1.50 - - [10/Nov/2026:10:05:00 +0700] &quot;GET /exec?cmd=;cat%20/etc/passwd HTTP/1.1&quot; 403 120'>Malicious Command Log</span>
                        </div>
                    </div>
                </div>

                <div style="display:flex; gap:10px; align-items:center; margin-top:20px;">
                    <button class="btn btn-primary" id="btnAnalyze" onclick="analyzeRequest()">
                        Analyze Request
                    </button>
                    <button class="btn btn-secondary" onclick="clearInput()">
                        Clear
                    </button>
                </div>
                <div class="spinner" id="spinSingle">Parsing syntax &amp; evaluating machine learning model...</div>

                <!-- ═══ Two-Stage Results Container ═══ -->
                <div class="results-container" id="resultsContainer">
                    
                    <!-- STAGE 1: Parser Stage (Chuẩn hóa cấu trúc) -->
                    <div class="section-header">
                        <div class="section-title">
                            <span class="step-badge">Stage 1</span>
                            Unified Normalization (Parser Output)
                        </div>
                        <button class="btn btn-secondary btn-sm" onclick="copyNormJson()">Copy JSON</button>
                    </div>

                    <div class="norm-panel">
                        <div class="norm-meta-row">
                            <span class="badge-type" id="nType">CURL</span>
                            <span class="badge-method" id="nMethod">POST</span>
                            <span class="norm-path-val" id="nPath">/login</span>
                            <span id="nContentType" style="font-size:11px;color:var(--text-3);margin-left:auto;font-family:var(--mono);"></span>
                        </div>
                        <pre class="norm-json-viewer" id="normJsonCode"></pre>
                    </div>

                    <!-- STAGE 2: Security Assessment (Feature Extraction & Classifier) -->
                    <div class="section-header">
                        <div class="section-title">
                            <span class="step-badge">Stage 2</span>
                            Threat Assessment (Feature Extractor + ML)
                        </div>
                    </div>

                    <div class="result-box" id="resultBox">
                        <div class="result-top">
                            <div>
                                <span class="result-tag" id="rTag"></span>
                                <div class="result-msg" id="rMsg"></div>
                                <div class="threat-locations-row hidden" id="threatLocRow">
                                    <span class="threat-loc-label">Threat Origin:</span>
                                    <div id="threatLocList" style="display:flex; gap:6px;"></div>
                                </div>
                            </div>
                            <div class="result-score" id="rScore">0%</div>
                        </div>

                        <div class="progress-track"><div class="progress-fill" id="rBar"></div></div>

                        <!-- Class Probabilities Breakdown -->
                        <div class="class-prob-section" id="classProbSection">
                            <div class="class-prob-title">Multi-Class Probability Distribution (6 Classes)</div>
                            <div class="class-prob-grid" id="classProbGrid"></div>
                        </div>

                        <!-- Feature Breakdown -->
                        <div class="feat-title">Engineered Feature Inspection (30 Features)</div>
                        <div class="result-features" id="rFeats"></div>
                    </div>

                </div>
            </div>
        </div>
    </div>

    <!-- ═══ Tab 2: Log Scan (with File Upload) ═══ -->
    <div id="tab-log" class="hidden">
        <div class="card">
            <div class="card-body">
                <div class="field">
                    <label class="field-label">Upload Log File or Select Sample</label>

                    <!-- Hidden file picker -->
                    <input type="file" id="logFileInput" accept=".log,.txt,.csv" style="display:none" onchange="handleFilePicked(event)">

                    <!-- Drag & Drop Zone -->
                    <div class="dropzone" id="dropzone" onclick="document.getElementById('logFileInput').click()">
                        <div class="drop-title" id="dropTitle">Drop Log File Here or Click to Browse</div>
                        <div class="drop-hint">Supports .log, .txt, .csv (cURL lists, Nginx, Apache, IIS, or raw requests)</div>
                    </div>

                    <!-- Selected file info bar -->
                    <div class="file-loaded-bar hidden" id="fileLoadedBar">
                        <div class="file-info-col">
                            <div class="file-name-text" id="loadedFileName">filename.log</div>
                            <div class="file-meta-text" id="loadedFileMeta">0 KB &middot; 0 lines</div>
                        </div>
                        <button class="btn-clear" title="Clear selection" onclick="clearSelectedFile(event)">&times;</button>
                    </div>
                </div>

                <div class="field" id="sampleSelectWrapper">
                    <label class="field-label">Or choose from server sample logs</label>
                    <select class="field-input" id="logSelect" onchange="onSampleSelected()">
                        <option value="logsfile.txt">logsfile.txt (cURL Commands: 10 Normal + 10 Attack)</option>
                        <option value="access.log">access.log (Nginx Web Server format)</option>
                        <option value="testlog.log">testlog.log (CSIC Security Benchmark format)</option>
                    </select>
                </div>

                <div style="display: flex; gap: 10px; align-items: center; margin-top: 18px;">
                    <button class="btn btn-primary" id="btnScan" onclick="scanLog()">
                        Scan Log File
                    </button>
                    <button class="btn btn-secondary hidden" id="btnExport" onclick="exportResults()">
                        Export CSV
                    </button>
                </div>
                <div class="spinner" id="spinLog">Scanning requests and classifying threats...</div>

                <div id="logResult" class="hidden">
                    <div class="stats">
                        <div class="stat"><div class="stat-num" id="sTotal">0</div><div class="stat-label">Total Requests</div></div>
                        <div class="stat"><div class="stat-num c-red"  id="sAttack">0</div><div class="stat-label">Attacks Detected</div></div>
                        <div class="stat"><div class="stat-num c-green" id="sNormal">0</div><div class="stat-label">Normal Requests</div></div>
                    </div>

                    <!-- Attack Breakdown -->
                    <div class="breakdown-row" id="breakdownRow"></div>

                    <div class="tbl-section">
                        <div class="tbl-header-bar">
                            <div class="tbl-head" id="tblHead">Detailed Log Events</div>
                        </div>
                        <div class="tbl-wrap">
                            <table>
                                <thead><tr><th style="width:140px">Classification</th><th style="width:75px">Score</th><th>Request Path</th></tr></thead>
                                <tbody id="tblBody"></tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="footer">
        <span>Dataset: Multi-Source Hybrid (130K rows: CSIC + PayloadsAllTheThings + PayloadBox)</span>
        <span>Classifier: LightGBM Multi-Class (6 Classes, 30 Features)</span>
    </div>
</div>

<script>
/* ── State ── */
let currentFormat = 'auto';
let uploadedFileContent = null;
let uploadedFileName = null;
let currentLogResults = null;
let lastNormalizedJson = null;

/* ── Tabs ── */
document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const t = btn.dataset.tab;
        document.getElementById('tab-single').classList.toggle('hidden', t !== 'single');
        document.getElementById('tab-log').classList.toggle('hidden', t !== 'log');
    });
});

/* ── Format Selector ── */
document.querySelectorAll('.fmt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.fmt-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFormat = btn.dataset.fmt;
    });
});

/* ── Sample Chips ── */
document.querySelectorAll('.chip[data-val]').forEach(c => {
    c.addEventListener('click', () => {
        const val = c.getAttribute('data-val');
        const fmt = c.getAttribute('data-fmt') || 'auto';
        document.getElementById('requestInput').value = val;
        
        document.querySelectorAll('.fmt-btn').forEach(b => {
            b.classList.toggle('active', b.dataset.fmt === fmt);
        });
        currentFormat = fmt;
        
        analyzeRequest();
    });
});

function clearInput() {
    document.getElementById('requestInput').value = '';
    document.getElementById('resultsContainer').classList.remove('show');
}

/* ── Category Tag Helper ── */
function getCategoryClass(atype) {
    const t = (atype || '').toLowerCase();
    if (t.includes('sql')) return 'sqli';
    if (t.includes('xss')) return 'xss';
    if (t.includes('command')) return 'cmdi';
    if (t.includes('path') || t.includes('traversal') || t.includes('lfi')) return 'lfi';
    if (t.includes('other') || t.includes('ssti') || t.includes('xxe') || t.includes('ssrf')) return 'other';
    return 'normal';
}

/* ── Request Analysis (Tab 1) ── */
async function analyzeRequest() {
    const rawText = document.getElementById('requestInput').value.trim();
    if (!rawText) return;

    const btn = document.getElementById('btnAnalyze');
    const spin = document.getElementById('spinSingle');
    btn.disabled = true;
    spin.classList.add('on');
    document.getElementById('resultsContainer').classList.remove('show');

    try {
        const res = await fetch('/api/predict', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ input: rawText, format: currentFormat })
        });
        const data = await res.json();

        // 1. Render Parser Stage (Normalized Request)
        const norm = data.normalized_request || {};
        lastNormalizedJson = norm;
        document.getElementById('nType').textContent = (norm.input_type || 'URL').toUpperCase();
        document.getElementById('nMethod').textContent = norm.method || 'GET';
        document.getElementById('nPath').textContent = norm.path || norm.url || '/';
        document.getElementById('nContentType').textContent = norm.content_type ? `Content-Type: ${norm.content_type}` : '';
        document.getElementById('normJsonCode').textContent = JSON.stringify(norm, null, 2);

        // 2. Render Security Assessment Stage
        const box = document.getElementById('resultBox');
        const tag = document.getElementById('rTag');
        const msg = document.getElementById('rMsg');
        const score = document.getElementById('rScore');
        const bar = document.getElementById('rBar');
        const probGrid = document.getElementById('classProbGrid');
        const feEl = document.getElementById('rFeats');
        const threatLocRow = document.getElementById('threatLocRow');
        const threatLocList = document.getElementById('threatLocList');

        const pct = (data.probability * 100).toFixed(1);
        const cls = data.is_attack ? 'attack' : 'normal';

        box.className = 'result-box is-' + cls;
        tag.className = 'result-tag ' + cls;
        tag.textContent = data.is_attack ? data.attack_type.toUpperCase() : 'SAFE / NORMAL';
        score.className = 'result-score ' + cls;
        score.textContent = pct + '%';

        msg.textContent = data.is_attack
            ? 'Malicious pattern detected: Classified as ' + data.attack_type + '.'
            : 'No attack signatures detected. Request conforms to normal benign web patterns.';

        bar.className = 'progress-fill ' + cls;
        bar.style.width = pct + '%';

        // Threat Origin Locations
        if (data.is_attack && data.threat_locations && data.threat_locations.length > 0) {
            threatLocRow.classList.remove('hidden');
            threatLocList.innerHTML = data.threat_locations.map(loc => `<span class="threat-loc-badge">${esc(loc)}</span>`).join('');
        } else {
            threatLocRow.classList.add('hidden');
            threatLocList.innerHTML = '';
        }

        // Multi-Class Probabilities
        probGrid.innerHTML = '';
        if (data.class_probabilities) {
            for (const [cName, pVal] of Object.entries(data.class_probabilities)) {
                const cPct = (pVal * 100).toFixed(1);
                const isHighlight = pVal > 0.3 && cName !== 'Normal';
                probGrid.innerHTML += '<div class="class-prob-card">' +
                    '<div class="class-prob-name">' + cName + '</div>' +
                    '<div class="class-prob-val' + (isHighlight ? ' highlight' : '') + '">' + cPct + '%</div>' +
                    '</div>';
            }
        }

        // Feature Inspection (30 Features)
        const attackKeywords = [
            'sql_keywords','js_keywords','cmd_keywords','path_traversal',
            'nosql_keywords','ssti_patterns','xxe_patterns','ssrf_patterns',
            'has_null_byte','double_encoded','has_unicode_escape','has_path_traversal'
        ];
        feEl.innerHTML = '';
        const feats = data.features || {};
        for (const [k, v] of Object.entries(feats)) {
            const hot = attackKeywords.includes(k) && v > 0;
            feEl.innerHTML += '<div class="feat-item"><span class="feat-name">' + k + '</span><span class="feat-val' + (hot ? ' hot' : '') + '">' + v + '</span></div>';
        }

        document.getElementById('resultsContainer').classList.add('show');
    } finally {
        btn.disabled = false;
        spin.classList.remove('on');
    }
}

function copyNormJson() {
    if (!lastNormalizedJson) return;
    navigator.clipboard.writeText(JSON.stringify(lastNormalizedJson, null, 2));
    alert('Normalized Request JSON copied to clipboard!');
}

/* ── Drag & Drop & File Upload Handlers (Tab 2) ── */
const dropzone = document.getElementById('dropzone');
['dragenter', 'dragover'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });
});
['dragleave', 'drop'].forEach(name => {
    dropzone.addEventListener(name, (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
    });
});
dropzone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
        processFile(files[0]);
    }
});

function handleFilePicked(event) {
    const files = event.target.files;
    if (files && files.length > 0) {
        processFile(files[0]);
    }
}

async function processFile(file) {
    if (!file) return;
    uploadedFileName = file.name;
    const text = await file.text();
    uploadedFileContent = text;

    const linesCount = text.split('\n').filter(l => l.trim().length > 0).length;
    const sizeKB = (file.size / 1024).toFixed(1);

    dropzone.classList.add('hidden');
    document.getElementById('fileLoadedBar').classList.remove('hidden');
    document.getElementById('loadedFileName').textContent = file.name;
    document.getElementById('loadedFileMeta').textContent = `${sizeKB} KB · ${linesCount.toLocaleString()} request lines`;
    document.getElementById('btnScan').textContent = `Scan Uploaded File (${linesCount} lines)`;
}

function clearSelectedFile(event) {
    if (event) event.stopPropagation();
    uploadedFileContent = null;
    uploadedFileName = null;
    document.getElementById('logFileInput').value = '';
    document.getElementById('fileLoadedBar').classList.add('hidden');
    dropzone.classList.remove('hidden');
    document.getElementById('btnScan').textContent = `Scan Log File`;
}

function onSampleSelected() {
    if (uploadedFileContent !== null) {
        clearSelectedFile();
    }
}

/* ── Log Scan (Tab 2) ── */
async function scanLog() {
    const btn = document.getElementById('btnScan');
    const spin = document.getElementById('spinLog');
    btn.disabled = true; spin.classList.add('on');
    document.getElementById('logResult').classList.add('hidden');
    document.getElementById('btnExport').classList.add('hidden');

    try {
        let res;
        if (uploadedFileContent !== null) {
            res = await fetch('/api/upload-log', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ filename: uploadedFileName, content: uploadedFileContent })
            });
        } else {
            const logName = document.getElementById('logSelect').value;
            res = await fetch('/api/log', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ log: logName })
            });
        }
        const data = await res.json();
        currentLogResults = data;
        renderLogResult(data);
    } finally {
        btn.disabled = false; spin.classList.remove('on');
    }
}

function renderLogResult(data) {
    document.getElementById('logResult').classList.remove('hidden');
    document.getElementById('btnExport').classList.remove('hidden');
    document.getElementById('sTotal').textContent = (data.total_requests || 0).toLocaleString();
    document.getElementById('sAttack').textContent = (data.attack_count || 0).toLocaleString();
    document.getElementById('sNormal').textContent = (data.normal_count || 0).toLocaleString();

    /* Multi-class breakdown pills */
    const bRow = document.getElementById('breakdownRow');
    bRow.innerHTML = '';
    if (data.attack_breakdown) {
        for (const [atype, cnt] of Object.entries(data.attack_breakdown)) {
            bRow.innerHTML += '<div class="breakdown-chip">' +
                '<span>' + atype + '</span>' +
                '<span class="breakdown-count">' + cnt + '</span>' +
                '</div>';
        }
    }

    document.getElementById('tblHead').textContent = 'Event Logs (' + (data.attack_count || 0) + ' threats classified)';

    const tbody = document.getElementById('tblBody');
    tbody.innerHTML = '';
    (data.details || []).forEach(r => {
        const tr = document.createElement('tr');
        const pct = (r.probability * 100).toFixed(0);
        const catClass = getCategoryClass(r.attack_type);
        const displayLabel = r.is_attack ? r.attack_type : 'Normal';
        const displayUrl = r.url || (r.normalized_request ? r.normalized_request.path : '/');
        tr.innerHTML =
            '<td><span class="tag-sm ' + catClass + '">' + esc(displayLabel) + '</span></td>' +
            '<td class="td-prob ' + (r.is_attack ? 'high' : 'low') + '">' + pct + '%</td>' +
            '<td class="td-url">' + esc(displayUrl) + '</td>';
        tbody.appendChild(tr);
    });
}

/* ── Export CSV Report ── */
function exportResults() {
    if (!currentLogResults || !currentLogResults.details) return;
    const rows = [["Status", "Attack_Type", "Threat_Probability", "Request_Path"]];
    currentLogResults.details.forEach(r => {
        const pth = r.url || (r.normalized_request ? r.normalized_request.path : "");
        rows.push([
            r.is_attack ? "ATTACK" : "NORMAL",
            r.attack_type || (r.is_attack ? "Malicious" : "Normal"),
            r.probability,
            `"${pth.replace(/"/g, '""')}"`
        ]);
    });
    const csvContent = "data:text/csv;charset=utf-8," + rows.map(e => e.join(",")).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    const fname = (currentLogResults.filename || "scan_results").replace(/\.[^/.]+$/, "") + "_report.csv";
    link.setAttribute("download", fname);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

function esc(t) { const d = document.createElement('div'); d.textContent = t; return d.innerHTML; }
</script>
</body>
</html>
"""


class WebHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(HTML_PAGE.encode('utf-8'))

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_len).decode('utf-8')
        data = json.loads(body) if body else {}

        if self.path == '/api/predict':
            raw_input = data.get('input', data.get('url', ''))
            fmt = data.get('format', 'auto')
            threshold = float(data.get('threshold', 0.35))
            res = detector.predict_request(raw_input, threshold=threshold, input_type=fmt)
            self._json(res)

        elif self.path == '/api/features':
            raw_input = data.get('input', data.get('url', ''))
            fmt = data.get('format', 'auto')
            req = RequestParser.parse(raw_input, input_type=fmt)
            feats = extract_features(req)
            self._json(feats)

        elif self.path == '/api/upload-log':
            content = data.get('content', '')
            filename = data.get('filename', 'uploaded.log')
            lines = content.splitlines()
            summary = detector.analyze_log_lines(lines, threshold=0.35)
            summary['filename'] = filename
            self._json(summary)

        elif self.path == '/api/log':
            log_name = data.get('log', 'access.log')
            base_dir = os.path.dirname(os.path.abspath(__file__))
            log_path = os.path.join(base_dir, log_name)
            summary = detector.analyze_log(log_path, threshold=0.35)
            summary['filename'] = log_name
            self._json(summary)
        else:
            self.send_response(404)
            self.end_headers()

    def _json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))


def run_server(port=5000):
    server = HTTPServer(('127.0.0.1', port), WebHandler)
    print("\n" + "=" * 55)
    print("  Web Attack Detection Dashboard (Pure B&W Minimalist)")
    print(f"  Running at: http://localhost:{port}")
    print("  Font: Montserrat | Theme: Pure Black & White")
    print("  Press Ctrl+C to stop")
    print("=" * 55 + "\n")
    server.serve_forever()


if __name__ == "__main__":
    run_server(5000)
