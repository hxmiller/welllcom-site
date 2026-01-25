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
    raw = (raw or "").strip().replace(" ", "").replace("(", "").replace(")", "").replace("-", "")
    if raw.startswith("00"):
        raw = "+" + raw[2:]
    return raw


def is_valid_phone(e164: str) -> bool:
    return bool(E164_RE.match(e164 or ""))


@dataclass
class CodeRecord:
    code_hash: str
    expires_at: int


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

    def put(self, phone: str, code_hash: str, ttl_seconds: int):
        exp = int(time.time()) + ttl_seconds
        if self._r:
            self._r.hset(self._key(phone), mapping={"code_hash": code_hash, "expires_at": str(exp)})
            self._r.expire(self._key(phone), ttl_seconds)
        else:
            self._mem[self._key(phone)] = CodeRecord(code_hash=code_hash, expires_at=exp)

    def get(self, phone: str) -> CodeRecord | None:
        if self._r:
            d = self._r.hgetall(self._key(phone))
            if not d:
                return None
            return CodeRecord(code_hash=d.get("code_hash", ""), expires_at=int(d.get("expires_at", "0") or 0))
        return self._mem.get(self._key(phone))

    def delete(self, phone: str):
        if self._r:
            self._r.delete(self._key(phone))
        else:
            self._mem.pop(self._key(phone), None)


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
        consent_ok = request.form.get("consent") == "yes"

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

        # generate code
        import secrets
        code = f"{secrets.randbelow(1_000_000):06d}"
        secret = os.getenv("CODE_HASH_SECRET", "dev-secret-change-me")
        code_hash = hash_code(secret, phone, code)
        codes.put(phone, code_hash, ttl_seconds=10 * 60)

        # A2P-friendly message: short, informational, includes HELP/STOP and rates disclosure.
        body = (
            f"WellCom verification code: {code}. Expires in 10 min. "
            "Reply STOP to opt out, HELP for help. Message and data rates may apply."
        )
        sent = send_sms(phone, body)

        if sent:
            flash("Verification code sent. Please enter it below.", "success")
        else:
            flash("SMS not sent (Twilio not configured yet). For testing, check server logs for the code.", "warning")
            app.logger.warning("DEV code for %s is %s", phone, code)

        return redirect(url_for("login"))

    @app.post("/login/verify")
    def verify_code_route():
        phone = normalize_phone(request.form.get("phone", ""))
        code = (request.form.get("code", "") or "").strip()

        if not is_valid_phone(phone) or not re.fullmatch(r"\d{6}", code):
            flash("Invalid phone number or code.", "danger")
            return redirect(url_for("login"))

        rec = codes.get(phone)
        if not rec:
            flash("No active code found (it may have expired). Please request a new code.", "danger")
            return redirect(url_for("login"))

        if int(time.time()) > rec.expires_at:
            codes.delete(phone)
            flash("That code expired. Please request a new code.", "danger")
            return redirect(url_for("login"))

        secret = os.getenv("CODE_HASH_SECRET", "dev-secret-change-me")
        expected = hash_code(secret, phone, code)
        if not hmac.compare_digest(expected, rec.code_hash):
            flash("Incorrect code.", "danger")
            return redirect(url_for("login"))

        codes.delete(phone)
        session["user_phone"] = phone
        flash("Verified. (Next: preferences page)", "success")
        return redirect(url_for("home"))

    # Friendly endpoints for templates
    app.add_url_rule("/login/send-code", endpoint="send_code", view_func=send_code_route, methods=["POST"])
    app.add_url_rule("/login/verify", endpoint="verify_code", view_func=verify_code_route, methods=["POST"])

    return app


app = make_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
