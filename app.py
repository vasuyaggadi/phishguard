from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

import requests
import os
import time
import re
import base64
import webbrowser

from pathlib import Path
from threading import Timer
from urllib.parse import urlparse
from dotenv import load_dotenv


# =====================================================
# PHISHGUARD - FLASK BACKEND
# =====================================================


# =====================================================
# SETUP
# =====================================================

BASE_DIR = Path(__file__).resolve().parent

ENV_FILE = BASE_DIR / ".env"

load_dotenv(dotenv_path=ENV_FILE)


app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static")
)

CORS(app)


# =====================================================
# VIRUSTOTAL CONFIGURATION
# =====================================================

API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    ""
).strip()


VT_BASE = "https://www.virustotal.com/api/v3"


HEADERS = {
    "x-apikey": API_KEY,
    "Accept": "application/json"
}


if API_KEY:

    print("==========================================")
    print("VirusTotal API key loaded successfully.")
    print("==========================================")

else:

    print("==========================================")
    print("WARNING: VIRUSTOTAL_API_KEY is missing.")
    print(f"Create .env here: {ENV_FILE}")
    print("==========================================")


# =====================================================
# HOME PAGE
# =====================================================

@app.route("/")
def home():

    return render_template("index.html")


# =====================================================
# HEALTH CHECK
# =====================================================

@app.route("/health")
def health():

    return jsonify({
        "status": "online",
        "virustotal_configured": bool(API_KEY)
    })


# =====================================================
# LOCAL PHISHING ANALYSIS
# =====================================================

def local_analysis(url):

    score = 0

    reasons = []

    lower_url = url.lower()


    # -------------------------------------------------
    # HTTPS
    # -------------------------------------------------

    if not lower_url.startswith("https://"):

        score += 15

        reasons.append(
            "Website does not use HTTPS."
        )


    # -------------------------------------------------
    # VERY LONG URL
    # -------------------------------------------------

    if len(url) > 100:

        score += 10

        reasons.append(
            "URL is unusually long."
        )


    # -------------------------------------------------
    # IP ADDRESS
    # -------------------------------------------------

    ip_pattern = (
        r"https?://"
        r"(\d{1,3}\.){3}"
        r"\d{1,3}"
    )


    if re.search(
        ip_pattern,
        url
    ):

        score += 25

        reasons.append(
            "URL uses an IP address instead of a domain."
        )


    # -------------------------------------------------
    # @ SYMBOL
    # -------------------------------------------------

    if "@" in url:

        score += 20

        reasons.append(
            "URL contains an @ symbol."
        )


    # -------------------------------------------------
    # SUSPICIOUS KEYWORDS
    # -------------------------------------------------

    keywords = [

        "login",
        "log-in",
        "verify",
        "verification",
        "account",
        "secure",
        "security",
        "update",
        "confirm",
        "password",
        "bank",
        "signin",
        "sign-in",
        "authenticate",
        "authentication",
        "wallet",
        "payment",
        "billing",
        "invoice",
        "recover",
        "unlock",
        "suspend",
        "urgent"

    ]


    found = []


    for keyword in keywords:

        if keyword in lower_url:

            found.append(keyword)


    if found:

        score += min(
            len(found) * 5,
            25
        )

        reasons.append(
            "Suspicious keywords: "
            + ", ".join(found)
        )


    # -------------------------------------------------
    # MULTIPLE HYPHENS
    # -------------------------------------------------

    parsed = urlparse(url)

    hostname = parsed.hostname or ""

    if hostname.count("-") >= 3:

        score += 10

        reasons.append(
            "Domain contains multiple hyphens."
        )


    # -------------------------------------------------
    # MANY SUBDOMAINS
    # -------------------------------------------------

    domain_parts = hostname.split(".")

    if len(domain_parts) >= 5:

        score += 10

        reasons.append(
            "Domain contains an unusually large number of subdomains."
        )


    # -------------------------------------------------
    # URL ENCODED CHARACTERS
    # -------------------------------------------------

    if "%" in url:

        score += 5

        reasons.append(
            "URL contains encoded characters."
        )


    # -------------------------------------------------
    # SUSPICIOUS PORT
    # -------------------------------------------------

    try:

        if parsed.port and parsed.port not in [80, 443]:

            score += 10

            reasons.append(
                "Website uses a non-standard port."
            )

    except ValueError:

        pass


    return min(
        score,
        100
    ), reasons


# =====================================================
# URL ID
# =====================================================

def get_url_id(url):

    return base64.urlsafe_b64encode(
        url.encode()
    ).decode().strip("=")


# =====================================================
# GET EXISTING URL REPORT
# =====================================================

def get_url_report(url):

    if not API_KEY:

        return {}


    url_id = get_url_id(url)


    try:

        response = requests.get(

            f"{VT_BASE}/urls/{url_id}",

            headers=HEADERS,

            timeout=30

        )


        print(
            "URL REPORT STATUS:",
            response.status_code
        )


        if response.status_code != 200:

            print(
                "URL REPORT RESPONSE:",
                response.text
            )

            return {}


        data = response.json()


        url_data = data.get(
            "data",
            {}
        )


        print(
            "URL REPORT RECEIVED:",
            bool(url_data)
        )


        return url_data


    except requests.exceptions.RequestException as e:

        print(
            "URL REPORT ERROR:",
            str(e)
        )

        return {}


# =====================================================
# SUBMIT URL FOR ANALYSIS
# =====================================================

def submit_url(url):

    if not API_KEY:

        raise Exception(
            "VirusTotal API key is not configured. "
            "Add VIRUSTOTAL_API_KEY to .env."
        )


    try:

        response = requests.post(

            f"{VT_BASE}/urls",

            headers=HEADERS,

            data={
                "url": url
            },

            timeout=30
        )


        print(
            "SUBMIT STATUS:",
            response.status_code
        )


        if response.status_code not in [200, 201]:

            try:

                error_data = response.json()

                message = (

                    error_data

                    .get(
                        "error",
                        {}
                    )

                    .get(
                        "message",
                        "VirusTotal submission failed."
                    )

                )

            except Exception:

                message = (
                    f"VirusTotal submission failed "
                    f"with HTTP {response.status_code}."
                )


            raise Exception(
                message
            )


        data = response.json()


        analysis_id = (

            data

            .get(
                "data",
                {}
            )

            .get(
                "id"
            )

        )


        if not analysis_id:

            raise Exception(
                "VirusTotal did not return an analysis ID."
            )


        return analysis_id


    except requests.exceptions.Timeout:

        raise Exception(
            "VirusTotal request timed out."
        )


    except requests.exceptions.ConnectionError:

        raise Exception(
            "Could not connect to VirusTotal."
        )


    except requests.exceptions.RequestException as e:

        raise Exception(
            f"VirusTotal request failed: {str(e)}"
        )


# =====================================================
# WAIT FOR VIRUSTOTAL ANALYSIS
# =====================================================

def wait_for_analysis(
    analysis_id,
    attempts=20,
    delay=2
):

    if not API_KEY:

        return {}


    for attempt in range(attempts):

        try:

            response = requests.get(

                f"{VT_BASE}/analyses/{analysis_id}",

                headers=HEADERS,

                timeout=30
            )


            if response.status_code != 200:

                print(
                    "ANALYSIS STATUS ERROR:",
                    response.status_code
                )

                print(
                    response.text
                )

                raise Exception(
                    "Could not retrieve VirusTotal analysis."
                )


            data = response.json()


            attributes = (

                data

                .get(
                    "data",
                    {}
                )

                .get(
                    "attributes",
                    {}
                )

            )


            status = attributes.get(
                "status",
                "queued"
            )


            print(
                f"ANALYSIS STATUS "
                f"{attempt + 1}/{attempts}:",
                status
            )


            if status == "completed":

                return attributes.get(
                    "stats",
                    {}
                )


            time.sleep(
                delay
            )


        except requests.exceptions.RequestException as e:

            raise Exception(
                f"VirusTotal analysis request failed: {str(e)}"
            )


    return {}


# =====================================================
# GET VENDORS
# =====================================================

def get_vendors(url_data):

    attributes = url_data.get(
        "attributes",
        {}
    )


    results = attributes.get(
        "last_analysis_results",
        {}
    )


    vendors = []


    for name, result in results.items():

        vendors.append({

            "vendor": name,

            "category": result.get(
                "category",
                "undetected"
            ),

            "result": result.get(
                "result",
                "-"
            )

        })


    # -------------------------------------------------
    # SORT
    # -------------------------------------------------

    def vendor_priority(item):

        category = item["category"]

        if category == "malicious":
            return 0

        if category == "suspicious":
            return 1

        if category == "harmless":
            return 2

        return 3


    vendors.sort(
        key=vendor_priority
    )


    return vendors


# =====================================================
# GET SERVING IP
# =====================================================

def get_serving_ips(url):

    if not API_KEY:

        return []


    url_id = get_url_id(url)


    # -------------------------------------------------
    # VIRUSTOTAL LAST SERVING IP
    # -------------------------------------------------

    try:

        response = requests.get(

            f"{VT_BASE}/urls/"
            f"{url_id}/last_serving_ip_address",

            headers=HEADERS,

            timeout=30
        )


        print(
            "LAST SERVING IP STATUS:",
            response.status_code
        )


        if response.status_code == 200:

            data = response.json()


            ip_data = data.get(
                "data",
                {}
            )


            attributes = ip_data.get(
                "attributes",
                {}
            )


            ip = attributes.get(
                "ip_address"
            )


            if ip:

                return [ip]


    except requests.exceptions.RequestException as e:

        print(
            "SERVING IP ERROR:",
            str(e)
        )


    # -------------------------------------------------
    # DOMAIN RESOLUTION FALLBACK
    # -------------------------------------------------

    parsed = urlparse(url)

    domain = parsed.hostname


    if not domain:

        return []


    try:

        response = requests.get(

            f"{VT_BASE}/domains/"
            f"{domain}/resolutions",

            headers=HEADERS,

            params={
                "limit": 10
            },

            timeout=30
        )


        print(
            "DOMAIN RESOLUTION STATUS:",
            response.status_code
        )


        if response.status_code != 200:

            return []


        data = response.json().get(
            "data",
            []
        )


        ips = []


        for item in data:

            attributes = item.get(
                "attributes",
                {}
            )


            ip = attributes.get(
                "ip_address"
            )


            if ip and ip not in ips:

                ips.append(ip)


        return ips


    except requests.exceptions.RequestException as e:

        print(
            "DOMAIN RESOLUTION ERROR:",
            str(e)
        )

        return []


# =====================================================
# PAGE STATS
# =====================================================

def get_page_stats(url_data):

    attributes = url_data.get(
        "attributes",
        {}
    )


    categories = attributes.get(
        "categories",
        {}
    )


    outgoing_links = attributes.get(
        "outgoing_links",
        []
    )


    return {

        "title": attributes.get(
            "title",
            "-"
        ),

        "reputation": attributes.get(
            "reputation",
            0
        ),

        "categories": list(
            categories.values()
        ),

        "times_submitted": attributes.get(
            "times_submitted",
            0
        ),

        "first_submission_date":
            attributes.get(
                "first_submission_date"
            ),

        "last_submission_date":
            attributes.get(
                "last_submission_date"
            ),

        "last_http_response_code":
            attributes.get(
                "last_http_response_code"
            ),

        "final_url":
            attributes.get(
                "last_final_url",
                "-"
            ),

        "outgoing_links":
            outgoing_links,

        "redirection_chain":
            attributes.get(
                "redirection_chain",
                []
            ),

        "tags":
            attributes.get(
                "tags",
                []
            )

    }


# =====================================================
# SCAN URL
# =====================================================

@app.route(
    "/scan",
    methods=["POST"]
)
def scan():

    data = request.get_json(
        silent=True
    ) or {}


    url = str(
        data.get(
            "url",
            ""
        )
    ).strip()


    # -------------------------------------------------
    # EMPTY URL
    # -------------------------------------------------

    if not url:

        return jsonify({

            "error": "URL is required."

        }), 400


    # -------------------------------------------------
    # ADD PROTOCOL IF MISSING
    # -------------------------------------------------

    if not re.match(
        r"^https?://",
        url,
        re.IGNORECASE
    ):

        url = "https://" + url


    # -------------------------------------------------
    # VALIDATE URL
    # -------------------------------------------------

    parsed = urlparse(url)


    if not parsed.hostname:

        return jsonify({

            "error": "Please enter a valid website URL."

        }), 400


    try:

        # =============================================
        # LOCAL ANALYSIS
        # =============================================

        local_score, reasons = local_analysis(
            url
        )


        # =============================================
        # DEFAULT VIRUSTOTAL VALUES
        # =============================================

        analysis_stats = {}

        url_data = {}

        vendors = []

        serving_ips = []


        virus_total_status = ""


        # =============================================
        # VIRUSTOTAL
        # =============================================

        if not API_KEY:

            virus_total_status = (
                "VirusTotal API key not configured. "
                "Add VIRUSTOTAL_API_KEY to .env."
            )


        else:

            # -----------------------------------------
            # SUBMIT
            # -----------------------------------------

            analysis_id = submit_url(
                url
            )


            # -----------------------------------------
            # WAIT
            # -----------------------------------------

            analysis_stats = wait_for_analysis(
                analysis_id
            )


            # -----------------------------------------
            # GET URL REPORT
            # -----------------------------------------

            url_data = get_url_report(
                url
            )


            # -----------------------------------------
            # VENDORS
            # -----------------------------------------

            vendors = get_vendors(
                url_data
            )


            # -----------------------------------------
            # SERVING IP
            # -----------------------------------------

            serving_ips = get_serving_ips(
                url
            )


            virus_total_status = (
                "VirusTotal analysis completed."
            )


        # =============================================
        # PAGE STATS
        # =============================================

        page_stats = get_page_stats(
            url_data
        )


        # =============================================
        # VIRUSTOTAL STATS
        # =============================================

        attributes = url_data.get(
            "attributes",
            {}
        )


        url_stats = attributes.get(
            "last_analysis_stats",
            {}
        )


        malicious = url_stats.get(

            "malicious",

            analysis_stats.get(
                "malicious",
                0
            )

        )


        suspicious = url_stats.get(

            "suspicious",

            analysis_stats.get(
                "suspicious",
                0
            )

        )


        undetected = url_stats.get(

            "undetected",

            analysis_stats.get(
                "undetected",
                0
            )

        )


        harmless = url_stats.get(

            "harmless",

            analysis_stats.get(
                "harmless",
                0
            )

        )


        # =============================================
        # RISK SCORE
        # =============================================

        final_score = local_score


        # -----------------------------------------
        # MALICIOUS
        # -----------------------------------------

        if malicious > 0:

            final_score = 100


            reasons.append(

                f"VirusTotal detected "
                f"{malicious} malicious "
                f"vendor result(s)."

            )


        # -----------------------------------------
        # SUSPICIOUS
        # -----------------------------------------

        elif suspicious > 0:

            final_score = max(
                final_score,
                70
            )


            reasons.append(

                f"VirusTotal detected "
                f"{suspicious} suspicious "
                f"vendor result(s)."

            )


        # =============================================
        # RISK LEVEL
        # =============================================

        if final_score <= 30:

            risk = "🟢 Low Risk"


        elif final_score <= 60:

            risk = "🟡 Medium Risk"


        else:

            risk = "🔴 High Risk"


        # =============================================
        # NO REASONS
        # =============================================

        if not reasons:

            reasons.append(
                "No obvious phishing indicators were detected."
            )


        # =============================================
        # DEBUG
        # =============================================

        print()
        print("==============================")
        print("FINAL SCAN DATA")
        print("==============================")

        print(
            "URL:",
            url
        )

        print(
            "Score:",
            final_score
        )

        print(
            "Risk:",
            risk
        )

        print(
            "Malicious:",
            malicious
        )

        print(
            "Suspicious:",
            suspicious
        )

        print(
            "Undetected:",
            undetected
        )

        print(
            "Harmless:",
            harmless
        )

        print(
            "Vendors:",
            len(vendors)
        )

        print(
            "Serving IPs:",
            serving_ips
        )

        print("==============================")
        print()


        # =============================================
        # RESPONSE
        # =============================================

        return jsonify({

            "url": url,

            "score": final_score,

            "risk": risk,

            "reasons": reasons,


            "virustotal": {

                "malicious": malicious,

                "suspicious": suspicious,

                "undetected": undetected,

                "harmless": harmless,

                "status": virus_total_status

            },


            "vendors": vendors,


            "serving_ips": serving_ips,


            "history": {

                "times_submitted":
                    page_stats.get(
                        "times_submitted",
                        0
                    ),

                "first_submission_date":
                    page_stats.get(
                        "first_submission_date"
                    ),

                "last_submission_date":
                    page_stats.get(
                        "last_submission_date"
                    )

            },


            "page_stats": page_stats

        })


    except Exception as e:

        print(
            "SCAN ERROR:",
            str(e)
        )


        return jsonify({

            "error": str(e)

        }), 500


# =====================================================
# START SERVER
# =====================================================

if __name__ == "__main__":

    print()
    print("==========================================")
    print("           PHISHGUARD STARTING")
    print("==========================================")
    print("URL: http://127.0.0.1:5000")
    print("==========================================")
    print()


    try:

        Timer(
            1,
            lambda: webbrowser.open(
                "http://127.0.0.1:5000"
            )
        ).start()

    except Exception:

        pass


    port = int(
        os.getenv(
            "PORT",
            "5000"
        )
    )


    app.run(

        host="0.0.0.0",

        port=port,

        debug=False

    )