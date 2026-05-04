
## Email Phishing Detector

Project Link: https://github.com/AsafAvieli/phishing_detector

A full-stack security tool that analyzes emails for phishing indicators. It integrates a custom-built FastAPI backend with a Gmail Contextual Add-on, providing two ways to scan emails:

* **Live Gmail Integration**: Real-time analysis of open emails directly from a side panel.
* **Manual Analysis Dashboard**: A web interface (Streamlit) for uploading and inspecting .eml files.

## Tech Stack
* **Backend**: Python (FastAPI) – Chosen for its speed, simple REST API design, and native async support, which keeps analysis responses fast even under load.
* **Frontend (Add-on)**: Google Apps Script – The only way to build a native Gmail integration; runs inside Google's infrastructure with direct access to message data.
* **Frontend (Web)**: Streamlit – Lets us build an interactive upload-and-analyze UI in pure Python, with no HTML, CSS, or JavaScript needed. This keeps the entire project in one language and makes the UI easy to extend.
* **Connectivity**: ngrok – Bridges the local FastAPI server to Google's cloud so the Gmail add-on can reach it during development without a full deployment.

## Detection Capabilities
The engine scans each email across multiple dimensions:
* **Suspicious Links**: Detects URLs using raw IP addresses or high-risk domains (e.g., .xyz, .top, .click).
* **Display Name Spoofing**: Flags when a sender's display name impersonates a known brand (e.g., "Microsoft Security Team") but the actual email domain doesn't match.
* **Typosquatting**: Catches sender domains that closely resemble legitimate ones (e.g., paypa1.com vs paypal.com) using fuzzy string matching.
* **Urgent Language**: Scans for pressure tactics and social engineering keywords designed to make the recipient act without thinking.
* **Header Inspection**: Analyzes inconsistencies between From, Reply-To, and Return-Path headers to detect spoofing.
* **Authentication Failures**: Checks SPF, DKIM, and DMARC results to verify whether the sender is who they claim to be.
* **Malicious Attachments**: Flags double-extension filenames (e.g., invoice.pdf.exe) used to disguise executables.

---

## How to Run

### Prerequisites
- Python 3.9+
- [ngrok](https://ngrok.com) account (free) with a static domain configured

### Installation
```bash
git clone https://github.com/AsafAvieli/phishing_detector
cd phishing_detector
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Starting the app

Open three terminal windows from the project root:

**Terminal 1 — FastAPI backend:**
```bash
source .venv/bin/activate
uvicorn api:app --reload --port 8000
```

**Terminal 2 — Streamlit web UI:**
```bash
source .venv/bin/activate
streamlit run app.py
```
Opens automatically at http://localhost:8501

**Terminal 3 — ngrok tunnel (required for Gmail add-on):**
```bash
ngrok http --url=<your-static-domain>.ngrok-free.dev 8000
```

### CLI Usage (single file scan)
```bash
python phishing_analyzer.py path/to/email.txt
```
Exit code `1` = phishing detected, `0` = clean.

---

## Gmail Add-on Setup 

### Step 1 — Create the Apps Script project
1. Go to https://script.google.com and click **New project**.
2. Delete the default code, then paste the full contents of `gmail_addon/Code.gs`.
3. Go to **Project Settings** (gear icon) → enable **"Show appsscript.json manifest file in editor"**.
4. Click on `appsscript.json` in the left panel and replace its contents with `gmail_addon/appsscript.json`.
5. Save (Ctrl+S).

### Step 2 — Install the add-on to your Gmail
1. Click **Deploy → Test deployments**.
2. Under **Application**, select **Gmail**.
3. Click **Install** — this installs it for your own Google account only.
4. Click **Done**.

### Step 3 — Use it
1. Open [Gmail](https://mail.google.com).
2. Click on any email.
3. A **Phishing Detector** panel appears on the right side of the screen.
4. The analysis runs automatically — you'll see the verdict, risk score, and any detected indicators.


