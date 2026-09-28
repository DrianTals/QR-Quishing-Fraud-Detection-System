"""Serve the scanner and local Random Forest prediction API."""

import json
import pickle
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from extract_features import extract_features
from train_random_forest import FEATURE_COLUMNS, MODEL_OUTPUT_PATH
from url_utils import extract_url_candidate

ROOT_DIR = Path(__file__).resolve().parent
MODEL = None
MODEL_METRICS = None

SIGNAL_LABELS = {
    "url_parseable": "URL could not be parsed",
    "has_ip": "Uses a raw IP address",
    "no_https": "Does not use HTTPS",
    "has_at": "Contains an @ symbol",
    "is_shortener": "Uses a known URL shortener",
    "bad_tld": "Uses a suspicious top-level domain",
    "too_many_subdomains": "Has excessive subdomains",
    "hyphen_heavy": "Has a hyphen-heavy domain",
    "brand_mismatch": "Brand name does not match its domain",
    "suspicious_keyword": "Contains an urgency or credential keyword",
    "punycode": "Uses punycode in the domain",
    "numeric_heavy": "Has an unusually numeric domain",
    "is_free_hosting": "Uses a listed free-hosting platform",
    "has_double_hyphen": "Contains a double hyphen in the domain",
}


def load_model(model_path=MODEL_OUTPUT_PATH):
    model_path = Path(model_path)
    if not model_path.is_file():
        raise FileNotFoundError(
            f"Model not found at {model_path}. Run train_random_forest.py first."
        )
    with model_path.open("rb") as model_file:
        return pickle.load(model_file)


def make_prediction(model, raw_url):
    normalized_url = extract_url_candidate(raw_url)
    features = extract_features(normalized_url)
    feature_row = pd.DataFrame(
        [[features.get(column, 0) for column in FEATURE_COLUMNS]],
        columns=FEATURE_COLUMNS,
    )
    probabilities = model.predict_proba(feature_row)[0]
    classes = list(model.classes_)
    if 1 not in classes:
        raise ValueError("The loaded model has no malicious (label 1) class.")

    probability = float(probabilities[classes.index(1)])
    score = round(probability * 100)
    prediction = int(model.predict(feature_row)[0])
    tier = "danger" if prediction == 1 else "caution" if score >= 20 else "safe"
    flags = []
    for feature, label in SIGNAL_LABELS.items():
        hit = not bool(features.get(feature)) if feature == "url_parseable" else bool(features.get(feature))
        flags.append({
            "label": label,
            "detail": "Detected in the URL." if hit else "Not detected.",
            "hit": hit,
            "weight": None,
        })
    return {
        "decoded": normalized_url,
        "score": score,
        "probability": probability,
        "prediction": prediction,
        "tier": tier,
        "flags": flags,
        "engine": "random_forest",
    }


class ScannerHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            page = (ROOT_DIR / "index.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
            return
        if self.path == "/health":
            self._send_json(200, {
                "model_loaded": MODEL is not None,
                "evaluation": MODEL_METRICS,
            })
            return
        self._send_json(404, {"error": "Not found."})

    def do_POST(self):
        if urlparse(self.path).path != "/api/analyze":
            self._send_json(404, {"error": "Not found."})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"error": "Invalid request length."})
            return
        if content_length <= 0 or content_length > 16_384:
            self._send_json(413, {"error": "Request must contain a URL under 16 KB."})
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(400, {"error": "Request body must be valid JSON."})
            return
        raw_url = payload.get("url") if isinstance(payload, dict) else None
        if not isinstance(raw_url, str) or not raw_url.strip():
            self._send_json(400, {"error": "Provide a non-empty URL string."})
            return
        if MODEL is None:
            self._send_json(503, {"error": "Model is not loaded. Train the model and restart the server."})
            return

        try:
            self._send_json(200, make_prediction(MODEL, raw_url.strip()))
        except Exception as error:
            self._send_json(500, {"error": f"Prediction failed: {error}"})

    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}")


def main():
    global MODEL, MODEL_METRICS
    try:
        MODEL = load_model()
    except (FileNotFoundError, pickle.UnpicklingError) as error:
        raise SystemExit(str(error)) from error

    metrics_path = MODEL_OUTPUT_PATH.with_suffix(".metrics.json")
    if metrics_path.is_file():
        try:
            MODEL_METRICS = json.loads(metrics_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            MODEL_METRICS = None

    server = ThreadingHTTPServer(("127.0.0.1", 8765), ScannerHandler)
    print("Scanner ready at http://127.0.0.1:8765")
    print("URL text is analyzed locally; the server does not open or fetch submitted links.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping scanner server.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
