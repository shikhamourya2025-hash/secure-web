# 🔒 SecureWeb – Automated Web Security Scanner

A beginner-friendly web security scanner built with Python and Streamlit.  
It scans any public URL and shows security issues in a clean web dashboard.

---

## 📋 Features

- ✅ Detects present and properly configured security headers
- ❌ Lists missing security headers
- ⚠️ Flags weakly configured security headers
- 🌐 Tests CORS policy (wildcard, origin reflection, credentials)
- 🍪 Checks Set-Cookie flags (Secure, HttpOnly, SameSite)

---

## 🗂️ Project Files

| File | Description |
|---|---|
| `web.py` | Main application (all code in one file) |
| `requirements.txt` | Python packages needed to run the app |
| `README.md` | This file – setup and usage guide |
| `project.md` | Full project overview and design notes |

---

## ⚙️ Requirements

- Python 3.8 or higher
- pip (comes with Python)

---

## 📦 Installation

**Step 1 – Clone or download the project files**

Place all files in the same folder.

**Step 2 – Install dependencies**

Open a terminal in that folder and run:

```bash
pip install -r requirements.txt
```

---

## 🚀 Running the App

```bash
streamlit run web.py
```

Streamlit will open the app in your browser at `http://localhost:8501`.

---

## 🔍 How to Use

1. Enter a full URL in the **Target URL** field (e.g. `https://example.com`)
2. Click **🔍 Scan**
3. Review the results in each section of the dashboard

---

## 📊 Dashboard Sections

### 1. Security Headers
Checks for 7 key HTTP security headers:

| Header | Purpose |
|---|---|
| `Strict-Transport-Security` | Forces HTTPS |
| `Content-Security-Policy` | Controls resource loading |
| `X-Content-Type-Options` | Prevents MIME sniffing |
| `X-Frame-Options` | Blocks clickjacking |
| `Referrer-Policy` | Controls referrer info |
| `Permissions-Policy` | Restricts browser features |
| `X-XSS-Protection` | Legacy XSS filter |

### 2. CORS Test Results
- Checks for wildcard `Access-Control-Allow-Origin: *`
- Tests if the server reflects back arbitrary `Origin` headers
- Flags dangerous `credentials + wildcard` combination

### 3. Set-Cookie Flags
For each cookie in the response, checks:
- **Secure** – cookie only sent over HTTPS
- **HttpOnly** – JavaScript cannot access the cookie
- **SameSite** – controls cross-site cookie sending

---

## ⚠️ Disclaimer

This tool is for **educational purposes and authorised testing only**.  
Only scan websites you own or have explicit permission to test.

---

## 📄 License

MIT License – free to use and modify.
