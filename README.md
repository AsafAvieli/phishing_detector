
## Overview

Project Link: https://github.com/AsafAvieli/phishing_detector

This project is a full-stack security solution designed to identify phishing indicators within Gmail. It bridges the gap between static email content and dynamic security analysis by integrating a custom-built FastAPI backend with a Gmail Contextual Add-on.

The system provides two methods of analysis:
* **Live Gmail Integration**: Real-time analysis of open emails via a side panel.
* **Manual Analysis Dashboard**: A web-based interface (Streamlit) for uploading and inspecting .eml files.

## Tech Stack
* **Backend**: Python (FastAPI) – Selected for high performance, asynchronous capabilities, and efficient REST API development.
* **Frontend (Add-on)**: Google Apps Script – Used to build a native integration within the Gmail Workspace.
* **Frontend (Web)**: Streamlit – Used for rapid prototyping of the manual analysis dashboard.
* **Connectivity**: ngrok – Provides a secure tunnel to expose the local development server to Google's cloud services during testing.

## Phishing Indicators (Core Requirements)
The system fully implements the key indicators defined in the project requirements:
* **Suspicious Links**: Detection of URLs using raw IP addresses and identification of uncommon top-level domains (e.g., .online, .xyz, .top, .link).
* **Spoofed Sender Detection**: Typosquatting engine using fuzzy string matching for domain similarity and display name analysis for inconsistencies.
* **Urgent Language Analysis**: Heuristic scanning for pressure tactics and social engineering keywords.

## Advanced Security Capabilities
Beyond the basic requirements, this engine incorporates advanced forensic checks:
* **Display Name Spoofing**: Detects when the sender's display name impersonates a known brand (e.g., "Microsoft Security Team") but the actual email domain doesn't match.
* **Deep Header Inspection**: Analyzes inconsistencies between From, Reply-To, and Return-Path headers to detect sophisticated spoofing.
* **Authentication Parsing**: Scans Authentication-Results for SPF, DKIM, and DMARC signals to verify sender legitimacy.
* **Forensic File Checks**: Flags double-extension patterns (e.g., invoice.pdf.exe) used to bypass user awareness.

---

## How to Run

### Every Session — 3 Terminals

**Terminal 1 — FastAPI backend:**
```bash
cd "/Users/asaf_avieli/Documents/cursor projects/task1_phishing_emails"
source .venv/bin/activate
uvicorn api:app --reload --port 8000
```

**Terminal 2 — Streamlit web UI:**
```bash
cd "/Users/asaf_avieli/Documents/cursor projects/task1_phishing_emails"
source .venv/bin/activate
streamlit run app.py
```
Opens automatically at http://localhost:8501

**Terminal 3 — ngrok tunnel (required for Gmail add-on):**
```bash
ngrok http --url=saturday-province-confined.ngrok-free.dev 8000
```

### CLI Usage (single file scan)
```bash
source .venv/bin/activate
python phishing_analyzer.py path/to/email.txt
```
Exit code `1` = phishing detected, `0` = clean.

