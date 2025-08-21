from flask import Flask, render_template, send_from_directory
from pathlib import Path
import json
import os

app = Flask(__name__, template_folder="templates", static_folder="static")
ALERTS_PATH = Path(__file__).parent.parent / "outputs" / "alerts.json"


@app.route("/")
def index():
    alerts = []
    if ALERTS_PATH.exists():
        with ALERTS_PATH.open("r", encoding="utf-8") as f:
            alerts = json.load(f)
    return render_template("index.html", alerts=alerts)


@app.route("/download/alerts.json")
def download_alerts():
    return send_from_directory(ALERTS_PATH.parent, ALERTS_PATH.name, as_attachment=True)


if __name__ == "__main__":
    app.run(debug=True)
