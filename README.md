# Was My Password Leaked?

A lightweight Flask web app that checks your password against the HaveIBeenPwned database and gives you an entropy score with personalised hardening tips.

**Your password never touches the network.** The app uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent to the HIBP API. The actual comparison happens locally on your machine.

## Features
- Breach check via HaveIBeenPwned (k-anonymity model)
- Entropy calculation in bits
- Character class detection (lowercase, uppercase, digits, symbols)
- Personalised hardening recommendations
- Live entropy bar as you type
- Facts and stats about password security with cited sources
- Clean white UI with scroll animations

## Run locally

```bash
cd wasmypasswordleaked
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
