"""
Was My Password Leaked? - backend
Checks passwords against HaveIBeenPwned using k-anonymity,
so your actual password never touches the network.
"""

from flask import Flask, render_template, request, jsonify
import hashlib
import requests
import math
import string

app = Flask(__name__)


# Reach out to HaveIBeenPwned and see if this password shows up in any breaches

def check_pwned(password: str) -> int | None:
    """
    Hashes the password with SHA-1, sends only the first 5 characters
    to HIBP, then checks the response locally on our end.
    Returns how many times it appeared in breaches, or None if the API was unreachable.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=5,
        )
        resp.raise_for_status()
    except requests.RequestException:
        return None  # API is down, just skip the breach check rather than blocking the user

    for line in resp.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0


# Work out how hard this password would be to brute force

def calculate_entropy(password: str) -> float:
    """
    Estimates password entropy in bits: length x log2(character pool size).
    The pool grows as more character types get mixed in.
    """
    pool = 0
    if any(c in string.ascii_lowercase for c in password):
        pool += 26
    if any(c in string.ascii_uppercase for c in password):
        pool += 26
    if any(c in string.digits for c in password):
        pool += 10
    if any(c in string.punctuation for c in password):
        pool += 32
    if any(ord(c) > 127 for c in password):
        pool += 64  # handles unicode characters and emoji

    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


# Turn the entropy + breach result into a simple strength label

def get_strength(entropy: float, pwned_count: int | None) -> str:
    if pwned_count:
        return "breached"
    if entropy < 28:
        return "very_weak"
    elif entropy < 36:
        return "weak"
    elif entropy < 60:
        return "fair"
    elif entropy < 80:
        return "strong"
    else:
        return "very_strong"


# Build a personalised list of tips based on what we found

def get_recommendations(
    password: str, entropy: float, pwned_count: int | None
) -> list[dict]:
    recs = []

    # Breach warning always goes at the top
    if pwned_count:
        recs.append({
            "type": "critical",
            "text": (
                f"This password appeared in {pwned_count:,} known data breaches. "
                "Change it immediately on every account where you use it."
            ),
        })

    # Check the length
    if len(password) < 12:
        recs.append({
            "type": "warning",
            "text": (
                f"Only {len(password)} characters. Try to get to at least 12, ideally 16 or more. "
                "Length matters more than anything else."
            ),
        })
    elif len(password) < 16:
        recs.append({
            "type": "info",
            "text": f"Good length ({len(password)} chars). Getting to 16+ would make brute-force practically infeasible.",
        })

    # Check which character types are missing
    if not any(c in string.ascii_uppercase for c in password):
        recs.append({"type": "warning", "text": "Throw in some uppercase letters. It roughly doubles the search space."})

    if not any(c in string.digits for c in password):
        recs.append({"type": "warning", "text": "Include at least one number to widen the character pool."})

    if not any(c in string.punctuation for c in password):
        recs.append({
            "type": "warning",
            "text": "Symbols like !@#$%^&* give you the biggest boost per character added.",
        })

    # Wrap up with positive feedback if everything looks good
    if entropy >= 80 and not pwned_count:
        recs.append({
            "type": "success",
            "text": "Excellent password. Store it in a password manager and never reuse it across sites.",
        })
    elif not recs:
        recs.append({
            "type": "info",
            "text": "Use a password manager to generate and store unique passwords for every account.",
        })

    return recs


# Routes

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not password:
        return jsonify({"error": "No password provided."}), 400
    if len(password) > 256:
        return jsonify({"error": "Password too long (max 256 chars)."}), 400

    pwned_count = check_pwned(password)
    entropy     = calculate_entropy(password)
    strength    = get_strength(entropy, pwned_count)
    recs        = get_recommendations(password, entropy, pwned_count)

    return jsonify({
        "entropy":         round(entropy, 1),
        "length":          len(password),
        "pwned_count":     pwned_count,
        "strength":        strength,
        "recommendations": recs,
        "char_sets": {
            "lowercase": any(c in string.ascii_lowercase for c in password),
            "uppercase": any(c in string.ascii_uppercase for c in password),
            "digits":    any(c in string.digits          for c in password),
            "symbols":   any(c in string.punctuation     for c in password),
        },
    })


if __name__ == "__main__":
    app.run(debug=True)
