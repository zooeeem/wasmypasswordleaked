# SecureScan — Password & Breach Risk Checker

A lightweight Flask web app that checks passwords against the HaveIBeenPwned database and computes an entropy score with hardening recommendations.

**Your password is never sent in plain text.** The app uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent to the HIBP API.

## Features
- Breach check via HaveIBeenPwned (k-anonymity model)
- Entropy calculation in bits
- Character class detection (lowercase, uppercase, digits, symbols)
- Personalised hardening recommendations
- Live entropy bar as you type
- Clean dark UI

## Run locally

```bash
cd SecureScan
pip install -r requirements.txt
python app.py
```

Then open http://localhost:5000

## Deploy free to Render

1. Push this folder to a GitHub repo
2. Go to render.com → New Web Service → connect your repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Done — free tier is enough for a portfolio project

> Add `gunicorn>=21.2.0` to requirements.txt before deploying.

## Built by
Althea Zoe Anasco — [zooeeem.github.io](https://zooeeem.github.io)
