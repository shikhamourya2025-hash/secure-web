import streamlit as st
import requests
from datetime import datetime

# ── Page config ─────────────────────────────────────────────────────────────
st.set_page_config(page_title="SecureWeb Scanner", page_icon="🔒", layout="wide")

st.title("🔒 SecureWeb – Automated Web Security Scanner")
st.markdown("Scan any public URL for common security misconfigurations in seconds.")

# ── Helper: send an HTTP request ─────────────────────────────────────────────
def fetch(url, headers=None):
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        return response, None
    except requests.exceptions.MissingSchema:
        return None, "Invalid URL – did you forget `https://`?"
    except requests.exceptions.ConnectionError:
        return None, "Could not connect to the host."
    except requests.exceptions.Timeout:
        return None, "The request timed out."
    except Exception as e:
        return None, str(e)

# ── Security headers we care about ───────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "description": "Forces HTTPS connections (HSTS).",
        "weak_check": lambda v: "max-age" not in v.lower(),
        "weak_hint": "Should include `max-age`. Example: `max-age=31536000; includeSubDomains`",
    },
    "Content-Security-Policy": {
        "description": "Controls which resources the browser may load.",
        "weak_check": lambda v: "unsafe-inline" in v or "unsafe-eval" in v,
        "weak_hint": "Avoid `unsafe-inline` and `unsafe-eval`.",
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing.",
        "weak_check": lambda v: v.strip().lower() != "nosniff",
        "weak_hint": "Value must be exactly `nosniff`.",
    },
    "X-Frame-Options": {
        "description": "Stops your page from being embedded in iframes (clickjacking).",
        "weak_check": lambda v: v.strip().upper() not in ("DENY", "SAMEORIGIN"),
        "weak_hint": "Use `DENY` or `SAMEORIGIN`.",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer info is sent.",
        "weak_check": lambda v: v.strip().lower() in ("unsafe-url", "no-referrer-when-downgrade", ""),
        "weak_hint": "Prefer `strict-origin-when-cross-origin` or stricter.",
    },
    "Permissions-Policy": {
        "description": "Restricts browser features (camera, mic, geolocation…).",
        "weak_check": lambda v: False,   # presence alone is considered good
        "weak_hint": "",
    },
    "X-XSS-Protection": {
        "description": "Legacy XSS filter (mostly superseded by CSP).",
        "weak_check": lambda v: v.strip() == "0",
        "weak_hint": "Use `1; mode=block` if you keep this header.",
    },
}

# ── CORS checker ─────────────────────────────────────────────────────────────
def check_cors(url):
    results = {}

    # 1. Wildcard check
    r, err = fetch(url)
    if err:
        return {"error": err}
    acao = r.headers.get("Access-Control-Allow-Origin", "")
    results["Access-Control-Allow-Origin"] = acao or "(not set)"
    results["Wildcard (*)"] = acao.strip() == "*"

    # 2. Origin reflection check
    r2, _ = fetch(url, headers={"Origin": "https://evil.example.com"})
    if r2:
        reflected = r2.headers.get("Access-Control-Allow-Origin", "")
        results["Reflects arbitrary Origin"] = reflected == "https://evil.example.com"
        results["Reflected value"] = reflected or "(not set)"

    # 3. Credentials with wildcard
    acac = r.headers.get("Access-Control-Allow-Credentials", "false")
    results["Access-Control-Allow-Credentials"] = acac
    results["Credentials + Wildcard (dangerous)"] = (
        acao.strip() == "*" and acac.strip().lower() == "true"
    )

    return results

# ── Set-Cookie flag checker ───────────────────────────────────────────────────
def check_cookies(response):
    cookie_results = []
    raw_cookies = response.headers.get("Set-Cookie", "")

    # requests merges duplicate headers; use raw response headers for multiple cookies
    all_set_cookie = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []

    # Fallback: split on a common pattern if getlist is unavailable
    if not all_set_cookie and raw_cookies:
        all_set_cookie = [raw_cookies]

    for cookie_str in all_set_cookie:
        parts = [p.strip().lower() for p in cookie_str.split(";")]
        name = cookie_str.split("=")[0].strip()

        has_secure   = "secure" in parts
        has_httponly = "httponly" in parts
        samesite     = next((p for p in parts if p.startswith("samesite")), None)
        samesite_val = samesite.split("=")[-1].strip() if samesite else "not set"

        cookie_results.append({
            "Cookie Name": name,
            "Secure":      "✅ Yes" if has_secure   else "❌ No",
            "HttpOnly":    "✅ Yes" if has_httponly  else "❌ No",
            "SameSite":    samesite_val.capitalize() if samesite else "❌ Not set",
        })
    return cookie_results

# ── UI: input form ────────────────────────────────────────────────────────────
with st.form("scan_form"):
    url_input = st.text_input(
        "Target URL",
        placeholder="https://example.com",
        help="Enter the full URL including https://",
    )
    submitted = st.form_submit_button("🔍 Scan")

if not submitted:
    st.info("Enter a URL above and click **Scan** to begin.")
    st.stop()

# ── Run the scan ──────────────────────────────────────────────────────────────
with st.spinner("Scanning…"):
    response, error = fetch(url_input)

if error:
    st.error(f"**Error:** {error}")
    st.stop()

# ── Dashboard header ──────────────────────────────────────────────────────────
st.success("Scan complete!")
col1, col2 = st.columns(2)
col1.metric("Target URL", url_input)
col2.metric("Scanned at", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))
st.markdown(f"**HTTP Status:** `{response.status_code}`  |  **Final URL:** `{response.url}`")
st.divider()

# ── Section 1: Security Headers ───────────────────────────────────────────────
st.subheader("🛡️ Security Headers")

present   = []
missing   = []
weak      = []

for header, meta in SECURITY_HEADERS.items():
    value = response.headers.get(header)
    if value is None:
        missing.append((header, meta["description"]))
    else:
        if meta["weak_check"](value):
            weak.append((header, value, meta["weak_hint"]))
        else:
            present.append((header, value, meta["description"]))

# Detected (good) headers
if present:
    st.markdown("**✅ Detected & properly configured**")
    for h, v, desc in present:
        with st.expander(f"`{h}`"):
            st.markdown(f"**Value:** `{v}`")
            st.markdown(f"**What it does:** {desc}")
else:
    st.warning("No well-configured security headers detected.")

st.divider()

# Missing headers
if missing:
    st.markdown("**❌ Missing headers**")
    for h, desc in missing:
        with st.expander(f"`{h}`"):
            st.markdown(f"**What it does:** {desc}")
            st.markdown("**Status:** ⚠️ Header is not present in the response.")
else:
    st.success("No missing security headers — great!")

st.divider()

# Weak headers
if weak:
    st.markdown("**⚠️ Weakly configured headers**")
    for h, v, hint in weak:
        with st.expander(f"`{h}`"):
            st.markdown(f"**Current value:** `{v}`")
            st.markdown(f"**Recommendation:** {hint}")
else:
    st.success("No weakly configured headers found.")

st.divider()

# ── Section 2: CORS Results ───────────────────────────────────────────────────
st.subheader("🌐 CORS Test Results")

cors = check_cors(url_input)

if "error" in cors:
    st.error(cors["error"])
else:
    c1, c2, c3 = st.columns(3)
    c1.metric("Allow-Origin",      cors.get("Access-Control-Allow-Origin", "N/A"))
    c2.metric("Allow-Credentials", cors.get("Access-Control-Allow-Credentials", "N/A"))
    c3.metric("Reflects evil.example.com?", "Yes ❌" if cors.get("Reflects arbitrary Origin") else "No ✅")

    if cors.get("Wildcard (*)"):
        st.warning("⚠️ **Wildcard origin (`*`)** – any website can read responses from this server.")
    if cors.get("Reflects arbitrary Origin"):
        st.error("❌ **Origin reflection detected** – the server mirrors back any Origin header, which may allow cross-origin attacks.")
    if cors.get("Credentials + Wildcard (dangerous)"):
        st.error("❌ **Credentials + Wildcard** – this combination is dangerous and browsers block it, but it signals a misconfiguration.")
    if not cors.get("Wildcard (*)") and not cors.get("Reflects arbitrary Origin"):
        st.success("✅ CORS policy appears properly restricted.")

    with st.expander("Raw CORS header values"):
        for k, v in cors.items():
            st.markdown(f"- **{k}:** `{v}`")

st.divider()

# ── Section 3: Set-Cookie Flags ───────────────────────────────────────────────
st.subheader("🍪 Set-Cookie Flags")

cookies = check_cookies(response)

if not cookies:
    st.info("No `Set-Cookie` headers found in the response.")
else:
    st.markdown(f"**{len(cookies)} cookie(s) found:**")
    for cookie in cookies:
        with st.expander(f"Cookie: `{cookie['Cookie Name']}`"):
            st.markdown(f"- **Secure:**   {cookie['Secure']}")
            st.markdown(f"- **HttpOnly:** {cookie['HttpOnly']}")
            st.markdown(f"- **SameSite:** {cookie['SameSite']}")

st.divider()
st.caption("SecureWeb Scanner · For educational and authorised testing only.")
