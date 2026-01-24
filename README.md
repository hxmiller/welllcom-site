# WellCom Website (Heroku + Flask)

This project is a clean, modern, light/blue-ish website shell for WellCom.

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="dev"
python app.py
```

Open http://127.0.0.1:5000

## Deploy to Heroku
Push this repo to GitHub, connect it to Heroku, and deploy.

### Required Config Vars (Heroku Settings → Config Vars)

**For production (recommended):**
- `FLASK_SECRET_KEY` = long random string
- `CODE_HASH_SECRET` = long random string (for hashing codes)
- `REDIS_URL` = add Heroku Redis addon (recommended for multi-dyno)

**Turnstile (human check):**
- `TURNSTILE_SITE_KEY`
- `TURNSTILE_SECRET_KEY`

**Twilio (SMS):**
- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_FROM_NUMBER` (A2P-approved sending number)

## Notes on A2P friendliness
The login flow includes:
- explicit consent checkbox before sending SMS
- STOP/HELP + Msg&data rates disclosure
- links to Privacy/Terms/Consent pages
- basic throttling and code expiry

Next step: build the *preferences* page that controls recipients and message options.
