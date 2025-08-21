# Log Web Server Parser

A Python-based command-line tool to parse Apache/Nginx access logs, detect suspicious activity, enrich with GeoIP data, and export alerts to JSON/CSV. It also includes a minimal Flask dashboard to view and filter the generated alerts.

## Features

  * **Log Parsing**: Supports both Apache and Nginx combined log formats.
  * **Threat Detection Rules**:
      * **Brute Force Attacks**: Detects clusters of HTTP 401 errors, indicating potential brute force attempts (MITRE ATT\&CK T1110).
      * **Directory Traversal**: Identifies attempts to access restricted directories using `../` patterns.
      * **SQL Injection (SQLi)**: Catches common SQLi patterns like `UNION`, `SELECT`, and `OR 1=1`.
      * **Suspicious User-Agents**: Flags requests from common security tools and scanners like `curl`, `sqlmap`, and `nmap`.
      * **5xx Error Bursts**: Monitors for a high rate of server-side errors (500-599), which could indicate a Denial of Service (DoS) attack or server misconfiguration.
  * **GeoIP Enrichment**: Optionally enriches alerts with geographic information (country, city) for the source IP address using a MaxMind GeoLite2 City database.
  * **Flexible Output**:
      * Exports alerts to **JSON** and **CSV** formats.
      * Provides a human-readable summary of alerts printed to the console.
  * **Web Dashboard**: A simple Flask-based web interface to view, search, and filter alerts.
  * **Customizable Thresholds**: Allows for tuning the sensitivity of the brute force and 5xx error burst detection rules via command-line arguments.

## Getting Started

### Prerequisites

  * Python 3.x
  * The required Python packages as listed in `requirements.txt`.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Revprm/lws-parser.git
    cd lws-parser
    ```
2.  **Create and activate a virtual environment:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```
3.  **Install the dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Parsing Log Files

To run the parser on a log file, use the following command structure:

```bash
python -m parser.parser --log <path-to-log-file> [options]
```

**Example:**

```bash
python -m parser.parser --log logs/apache_access.log --print \
  --out-json outputs/alerts.json --out-csv outputs/alerts.csv
```

### Command-Line Arguments

  * `--log`: (Required) Path(s) to one or more log files.
  * `--format`: Log format (`auto`, `apache`, `nginx`). Defaults to `auto`.
  * `--out-json`: Path for the JSON output file. Defaults to `outputs/alerts.json`.
  * `--out-csv`: Path for the CSV output file.
  * `--geoip-db`: Path to the MaxMind GeoLite2-City.mmdb file for GeoIP enrichment.
  * `--bf-threshold`: Threshold for brute force detection. Default is 10.
  * `--bf-window`: Time window in seconds for brute force detection. Default is 60.
  * `--burst5xx`: Threshold for 5xx error burst detection. Default is 30.
  * `--burst5xx-window`: Time window in seconds for 5xx error burst detection. Default is 60.
  * `--port-scan-threshold`: Threshold for port scan detection. Default is 15.
  * `--port-scan-window`: Time window in seconds for port scan detection. Default is 300.
  * `--print`: Print a human-readable summary of the alerts to the console.

### Viewing the Dashboard

The Flask dashboard provides a simple way to view and filter the generated alerts.

1.  **Run the Flask application:**
    ```bash
    python dashboard/app.py
    ```
2.  **Open your web browser** and navigate to `http://127.0.0.1:5000`.

The dashboard will display the alerts from the `outputs/alerts.json` file.