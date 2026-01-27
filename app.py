import os
import re
import time
import hmac
import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, session
from content import PAGES

# Optional dependencies:
#   pip install twilio requests redis gunicorn
try:
    import requests
except Exception:  # pragma: no cover
    requests = None

try:
    from twilio.rest import Client as TwilioClient
except Exception:  # pragma: no cover
    TwilioClient = None

try:
    import redis
except Exception:  # pragma: no cover
    redis = None


E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")


def normalize_phone(raw: str) -> str:
    s = (raw or "").strip()

    # Convert leading 00… to +… (international style)
    if s.startswith("00"):
        s = "+" + s[2:]

    # If it already has a +, keep the plus and strip everything else non-digit
    if s.startswith("+"):
        digits = re.sub(r"\D", "", s[1:])
        return "+" + digits

    # Otherwise, strip all non-digits
    digits = re.sub(r"\D", "", s)

    # US-friendly rules:
    # - 10 digits => assume US, prefix +1
    # - 11 digits starting with 1 => prefix +
    if len(digits) == 10:
        return "+1" + digits
    if len(digits) == 11 and digits.startswith("1"):
        return "+" + digits

    # Fallback: return digits as-is (will fail validation if not E.164)
    return digits


def is_valid_phone(e164: str) -> bool:
    return bool(E164_RE.match(e164 or ""))

@dataclass
class CodeRecord:
    code_hash: str
    expires_at: int
    action: str = ""        # "opt_in" | "opt_out" | "hard_delete"
    pending_name: str = ""  # optional, but required for first-time opt-in

class CodeStore:
    """
    Stores pending verification codes.
    - If REDIS_URL is configured, uses Redis (recommended on Heroku).
    - Otherwise falls back to in-memory dict (single dyno only).
    """
    def __init__(self):
        self._mem = {}
        self._r = None
        if redis and os.getenv("REDIS_URL"):
            self._r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

    def _key(self, phone: str) -> str:
        return f"login_code:{phone}"

    def put(self, phone: str, code_hash: str, ttl_seconds: int, action: str, pending_name: str):
        exp = int(time.time()) + ttl_seconds
        if self._r:
            self._r.hset(self._key(phone), mapping={
                "code_hash": code_hash,
                "expires_at": str(exp),
                "action": action,
                "pending_name": pending_name or "",
            })
            self._r.expire(self._key(phone), ttl_seconds)
        else:
            self._mem[self._key(phone)] = CodeRecord(
                code_hash=code_hash,
                expires_at=exp,
                action=action,
                pending_name=pending_name or "",
            )

    def get(self, phone: str) -> CodeRecord | None:
        if self._r:
            d = self._r.hgetall(self._key(phone))
            if not d:
                return None
            return CodeRecord(
                code_hash=d.get("code_hash", ""),
                expires_at=int(d.get("expires_at", "0") or 0),
                action=d.get("action", "") or "",
                pending_name=d.get("pending_name", "") or "",
            )
        return self._mem.get(self._key(phone))


class RateLimiter:
    """
    Very small, A2P-friendly throttle to prevent SMS abuse.
    Uses Redis if available; otherwise in-memory.
    """
    def __init__(self):
        self._mem = {}
        self._r = None
        if redis and os.getenv("REDIS_URL"):
            self._r = redis.from_url(os.environ["REDIS_URL"], decode_responses=True)

    def _key(self, scope: str) -> str:
        return f"rl:{scope}"

    def allow(self, scope: str, limit: int, window_seconds: int) -> bool:
        now = int(time.time())
        bucket = now // window_seconds
        key = self._key(f"{scope}:{bucket}")
        if self._r:
            n = self._r.incr(key)
            if n == 1:
                self._r.expire(key, window_seconds)
            return n <= limit
        # mem
        n = self._mem.get(key, 0) + 1
        self._mem[key] = n
        # crude cleanup:
        for k in list(self._mem.keys()):
            if k.startswith(self._key(scope)) and k != key:
                self._mem.pop(k, None)
        return n <= limit


def hash_code(secret: str, phone: str, code: str) -> str:
    msg = f"{phone}:{code}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_turnstile(token: str, remote_ip: str | None) -> bool:
    secret = os.getenv("TURNSTILE_SECRET_KEY", "")
    if not secret:
        return False
    if not requests:
        return False
    try:
        resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": secret, "response": token, "remoteip": remote_ip or ""},
            timeout=10,
        )
        data = resp.json()
        return bool(data.get("success"))
    except Exception:
        return False


def send_sms(to_phone: str, body: str) -> bool:
    """
    Sends SMS via Twilio if configured.
    Required env vars:
      - TWILIO_ACCOUNT_SID
      - TWILIO_AUTH_TOKEN
      - TWILIO_FROM_NUMBER (your A2P-approved sending number)
    """
    sid = os.getenv("TWILIO_ACCOUNT_SID", "")
    token = os.getenv("TWILIO_AUTH_TOKEN", "")
    from_num = os.getenv("TWILIO_FROM_NUMBER", "")
    if not (TwilioClient and sid and token and from_num):
        return False
    try:
        client = TwilioClient(sid, token)
        client.messages.create(
            to=to_phone,
            from_=from_num,
            body=body,
        )
        return True
    except Exception:
        return False


def make_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("FLASK_SECRET_KEY", os.urandom(32))

    codes = CodeStore()
    rl = RateLimiter()

    # --- routes ---
    @app.before_request
    def force_https():
        if request.headers.get("X-Forwarded-Proto") == "http":
            return redirect(request.url.replace("http://", "https://"), code=301)
    
    @app.context_processor
    def inject_globals():
        return {
            "current_year": datetime.now(timezone.utc).year,
        }

    @app.get("/")
    def home():
        p = PAGES["home"]
        return render_template(
            "home.html",
            title="WellCom",
            active_page="home",
            heading=p.get("heading", ""),
            paragraphs=p.get("paragraphs", []),
            bullets=p.get("bullets", []),
            footer=p.get("footer", []),
        )

    def _content(page_key: str, active: str):
        p = PAGES[page_key]
        return render_template(
            "content.html",
            title=f"WellCom – {p['heading']}",
            active_page=active,
            heading=p["heading"],
            paragraphs=p.get("paragraphs", []),
            bullets=p.get("bullets", []),
            footer=p.get("footer", []),
        )
 
    @app.get("/privacy")
    def privacy():
        return _content("privacy", "privacy")

    @app.get("/terms")
    def terms():
        return _content("terms", "terms")

    @app.get("/consent")
    def consent():
        return _content("consent", "consent")

    @app.get("/help")
    def help():
        return _content("help", "help")

    @app.get("/contact")
    def contact():
        return _content("contact", "contact")

    @app.get("/login")
    def login():
        return render_template(
            "login.html",
            title="WellCom – Login",
            active_page="login",
            turnstile_site_key=os.getenv("TURNSTILE_SITE_KEY", ""),
        )

    @app.post("/login/send-code")
    def send_code_route():
        phone = normalize_phone(request.form.get("phone", ""))
        name = (request.form.get("name") or "").strip()
        action = (request.form.get("action") or "opt_in").strip().lower()
        consent_ok = request.form.get("consent") == "yes"
    
        if action not in ("opt_in", "opt_out", "hard_delete"):
            flash("Please choose a valid action.", "danger")
            return redirect(url_for("login"))
    
        if not is_valid_phone(phone):
            flash("Please enter a valid mobile number in international format (e.g. +13125550123).", "danger")
            return redirect(url_for("login"))
    
        if not consent_ok:
            flash("Consent is required to send a verification code.", "danger")
            return redirect(url_for("login"))
    
        # Human check (Turnstile)
        site_key = os.getenv("TURNSTILE_SITE_KEY", "")
        secret_key = os.getenv("TURNSTILE_SECRET_KEY", "")
        if site_key and secret_key:
            token = request.form.get("cf-turnstile-response", "")
            ok = verify_turnstile(token, request.remote_addr)
            if not ok:
                flash("Human verification failed. Please try again.", "danger")
                return redirect(url_for("login"))
        else:
            flash("Human check not configured yet; enable Turnstile in Config Vars for production.", "warning")
    
        # rate limits (per phone and per IP)
        if not rl.allow(f"ip:{request.remote_addr}", limit=5, window_seconds=15 * 60):
            flash("Too many attempts from this network. Please try again later.", "danger")
            return redirect(url_for("login"))
        if not rl.allow(f"phone:{phone}", limit=3, window_seconds=15 * 60):
            flash("Too many codes sent to this number. Please try again later.", "danger")
            return redirect(url_for("login"))
    
        # ---- NEW: delegate code generation + SMS to subscription-backend ----
        subs_base = os.getenv("SUBSCRIPTIONS_BACKEND_URL", "").rstrip("/")
        subs_key = os.getenv("SUBSCRIPTIONS_API_KEY", "")
        if not subs_base or not subs_key:
            flash("Server not configured (missing SUBSCRIPTIONS_BACKEND_URL or SUBSCRIPTIONS_API_KEY).", "danger")
            return redirect(url_for("login"))
    
        try:
            import requests
            r = requests.post(
                f"{subs_base}/api/v1/auth/send_code",
                headers={"X-Api-Key": subs_key},
                json={"phone": phone, "name": name, "action": action},
                timeout=15,
            )
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        except Exception as e:
            app.logger.exception("send_code: subscription-backend call failed")
            flash(f"Could not reach verification service. Please try again. ({e})", "danger")
            return redirect(url_for("login"))
    
        if r.status_code != 200 or not data.get("ok"):
            err = data.get("error") or f"HTTP {r.status_code}"
            flash(f"Could not send verification code: {err}", "danger")
            return redirect(url_for("login"))
    
        # Success: show verify page
        phone_e164 = data.get("phone_e164") or phone
        flash("Verification code sent. Please enter it below.", "success")
        return render_template("verify.html", phone=phone_e164, active_page="login", current_year=datetime.now().year)

    @app.post("/login/verify")
    def verify_code_route():
        phone = normalize_phone(request.form.get("phone", ""))
        code = (request.form.get("code", "") or "").strip()
    
        # Validate: 4-digit code (matches your verify.html and backend)
        if not is_valid_phone(phone):
            flash("Please enter a valid mobile number.", "danger")
            return redirect(url_for("login"))
    
        if not re.fullmatch(r"\d{4}", code):
            flash("Please enter the 4-digit code.", "danger")
            return render_template(
                "verify.html",
                phone=phone,
                active_page="login",
                current_year=datetime.now().year,
            )
    
        subs_base = os.getenv("SUBSCRIPTIONS_BACKEND_URL", "").rstrip("/")
        subs_key = os.getenv("SUBSCRIPTIONS_API_KEY", "")
        if not subs_base or not subs_key:
            flash("Server not configured (missing SUBSCRIPTIONS_BACKEND_URL or SUBSCRIPTIONS_API_KEY).", "danger")
            return redirect(url_for("login"))
    
        try:
            import requests
            r = requests.post(
                f"{subs_base}/api/v1/auth/verify_code",
                headers={"X-Api-Key": subs_key},
                json={"phone": phone, "code": code},
                timeout=15,
            )
            data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        except Exception as e:
            app.logger.exception("verify_code: subscription-backend call failed")
            flash("Could not reach verification service. Please try again.", "danger")
            return render_template(
                "verify.html",
                phone=phone,
                active_page="login",
                current_year=datetime.now().year,
            )
    
        if r.status_code != 200 or not data.get("ok"):
            err = data.get("error") or f"HTTP {r.status_code}"
            flash(f"Verification failed: {err}", "danger")
            # Keep user on the verify page so they can retry
            return render_template(
                "verify.html",
                phone=phone,
                active_page="login",
                current_year=datetime.now().year,
            )
    
        action = (data.get("action") or "").strip().lower()
        status = data.get("status") or ""
        token = data.get("token") or ""   # token may exist, but we won't use it for UI anymore
        phone_e164 = data.get("phone_e164") or phone
        name = data.get("name") or ""

        # If user chose hard delete, we're done.
        if action == "hard_delete":
            flash("Account deleted.", "success")
            return redirect(url_for("login"))

        # Mark session as verified (optional)
        session["user_phone"] = phone_e164

        # Page 3: receipt (stay on wellcom-site)
        return render_template(
            "receipt.html",
            title="WellCom – Preferences updated",
            active_page="login",
            phone=phone_e164,
            name=name,
            action=action,
            status=status,
            current_year=datetime.now().year,
        )

    # Friendly endpoints for templates
    app.add_url_rule("/login/send-code", endpoint="send_code", view_func=send_code_route, methods=["POST"])
    app.add_url_rule("/login/verify", endpoint="verify_code", view_func=verify_code_route, methods=["POST"])

    return app


app = make_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
