# 📁 SecureWeb – Project Overview

## Project Summary

**SecureWeb** is a lightweight, beginner-friendly automated web security scanner.  
It is built entirely in Python using the Streamlit framework and the Requests library.  
The entire application lives in a single file (`web.py`) to keep things simple.

---

## 🎯 Goal

To give beginners a hands-on tool that demonstrates real-world web security concepts  
by scanning live websites and showing results in a clean, readable dashboard.

---

## 🏗️ Architecture

```
SecureWeb/
│
├── web.py              ← Entire app (UI + scanning logic)
├── requirements.txt    ← Dependencies
├── README.md           ← Setup and usage guide
└── project.md          ← This file
```

The app follows a simple **request → analyse → display** flow:

```
User enters URL
      ↓
fetch() sends HTTP GET request
      ↓
┌─────────────────────────────────┐
│  Analyse response headers       │
│  ├── Security headers check     │
│  ├── CORS test (extra request)  │
│  └── Set-Cookie flags check     │
└─────────────────────────────────┘
      ↓
Streamlit renders dashboard
```

---

## 🔧 Technologies Used

| Technology | Version | Purpose |
|---|---|---|
| Python | 3.8+ | Programming language |
| Streamlit | 1.32+ | Web dashboard UI |
| Requests | 2.31+ | HTTP requests |
| datetime | (built-in) | Scan timestamp |

---

## 📦 Modules & Functions

### `fetch(url, headers=None)`
Sends an HTTP GET request to the target URL.  
Returns `(response, None)` on success or `(None, error_message)` on failure.  
Handles common errors: invalid URL, connection failure, timeout.

### `SECURITY_HEADERS` (dictionary)
Defines the 7 security headers to check.  
Each entry contains:
- `description` – what the header does
- `weak_check` – a lambda function that returns `True` if the value is weak
- `weak_hint` – advice on how to fix a weak value

### `check_cors(url)`
Sends two requests:
1. A plain request to read `Access-Control-Allow-Origin`
2. A request with `Origin: https://evil.example.com` to test for reflection

Returns a dictionary of CORS-related findings.

### `check_cookies(response)`
Parses all `Set-Cookie` headers from the response.  
For each cookie, checks for the `Secure`, `HttpOnly`, and `SameSite` flags.  
Returns a list of dictionaries, one per cookie.

---

## 🔍 Security Checks Explained

### Security Headers
HTTP response headers that instruct the browser on how to behave securely.  
Missing or misconfigured headers are a common finding in security audits.

### CORS (Cross-Origin Resource Sharing)
A browser policy that controls which origins can read a server's responses.  
Misconfigurations (like wildcard `*` with credentials) can allow data theft.

### Set-Cookie Flags
Flags attached to cookies that control how the browser handles them:
- **Secure** – prevents sending over plain HTTP
- **HttpOnly** – hides cookies from JavaScript (protects against XSS theft)
- **SameSite** – restricts cross-site cookie sending (protects against CSRF)

---

## 🚀 Future Improvements (Ideas)

- [ ] Add SSL/TLS certificate expiry check
- [ ] Add subdomain enumeration
- [ ] Export results as PDF or JSON report
- [ ] Add severity scoring (High / Medium / Low)
- [ ] Support scanning multiple URLs in one session
- [ ] Add a history log of previous scans

---

## ⚠️ Limitations

- Only checks HTTP **response headers** — does not crawl pages or test forms
- Some websites block automated requests (returns connection errors)
- CORS reflection test uses a single fake origin — not exhaustive
- Does not test authenticated endpoints

---

## 📄 License

MIT License – free to use, modify, and distribute for educational purposes.
