import os
import sys
import json
import requests

def resource_path(relative_path):

    try:

        base_path = sys._MEIPASS

    except Exception:

        base_path = os.path.abspath(".")

    return os.path.join(
        base_path,
        relative_path
    )
# --------------------------------------------------
# ASN DIRECTORY
# --------------------------------------------------

ASN_DB = {}

try:

    with open(
            resource_path(
                "data/ip-trackers-asn-directory.json"
            ),
            "r",
            encoding="utf-8"
    ) as f:

        data = json.load(f)

        for entry in data["entries"]:

            ASN_DB[
                str(entry["asn"])
            ] = entry

except Exception:

    ASN_DB = {}


# --------------------------------------------------
# ASN LOOKUP
# --------------------------------------------------

def get_asn_info(asn):

    if not asn:
        return None

    asn = str(asn).upper()

    if asn.startswith("AS"):
        asn = asn[2:]

    return ASN_DB.get(asn)


# --------------------------------------------------
# RISK LEVEL
# --------------------------------------------------

def risk_level(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    elif score >= 10:
        return "LOW"

    return "SAFE"


# --------------------------------------------------
# ENDPOINT CLASSIFICATION
# --------------------------------------------------

def classify_endpoint(info):

    isp = str(
        info.get("isp", "")
    ).lower()

    infrastructure = [
        "google",
        "amazon",
        "cloudflare",
        "akamai",
        "microsoft",
        "meta",
        "github",
        "digitalocean",
        "oracle",
        "linode"
    ]

    residential = [
        "jio",
        "airtel",
        "vodafone",
        "bsnl",
        "comcast",
        "spectrum"
    ]

    for provider in infrastructure:

        if provider in isp:

            return "INFRASTRUCTURE"

    for provider in residential:

        if provider in isp:

            return "RESIDENTIAL"

    return "UNKNOWN"


# --------------------------------------------------
# IP LOOKUP
# --------------------------------------------------

def get_ip_info(ip):

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )

        if response.status_code != 200:
            return None

        data = response.json()

        return {
            "ip": ip,
            "country": data.get(
                "country",
                "Unknown"
            ),
            "isp": data.get(
                "isp",
                "Unknown"
            ),
            "asn": data.get(
                "as",
                "Unknown"
            )
        }

    except Exception as e:

        print(
            f"IP INFO ERROR: {e}"
        )

        print(
            f"[IP LOOKUP TIMEOUT] {ip}"
        )

        return None


# --------------------------------------------------
# THREAT INTELLIGENCE
# --------------------------------------------------

class ThreatIntel:

    SAFE_ISPS = [

        "Google",
        "Microsoft",
        "Amazon",
        "Cloudflare",
        "Akamai",
        "Meta",
        "Discord",
        "Valve",
        "Steam",
        "GitHub",
        "DigitalOcean",
        "Oracle",
        "Linode"
    ]

    @staticmethod
    def score_ip(ip):

        try:

            info = get_ip_info(ip)

            if not info:

                return {
                    "ip": ip,
                    "score": 50,
                    "level": "MEDIUM",
                    "country": "Unknown",
                    "isp": "Unknown",
                    "asn": "Unknown",
                    "type": "UNKNOWN",
                    "asn_name": "Unknown",
                    "asn_category": "Unknown",
                    "asn_region": "Unknown"
                }

            score = 0

            country = info["country"]
            isp = info["isp"]
            asn = info["asn"]

            # ---------------------------
            # Country
            # ---------------------------

            if country == "Unknown":
                score += 20

            # ---------------------------
            # ISP
            # ---------------------------

            trusted = False

            for company in ThreatIntel.SAFE_ISPS:

                if company.lower() in isp.lower():

                    trusted = True
                    break

            if trusted:

                score -= 20

            else:

                score += 10

            # ---------------------------
            # ASN DATABASE
            # ---------------------------

            asn_info = get_asn_info(asn)

            asn_name = "Unknown"
            asn_category = "Unknown"
            asn_region = "Unknown"

            if asn_info:

                asn_name = asn_info["name"]
                asn_category = asn_info["category"]
                asn_region = asn_info["region"]

                if asn_category == "Cloud & CDN":

                    score -= 15

                elif asn_category == "Backbone":

                    score -= 10

                elif asn_category == "Residential ISP":

                    score += 0

                elif asn_category == "Mobile ISP":

                    score += 5

            else:

                score += 10

            score = max(0, score)

            return {

                "ip": ip,

                "score": score,

                "level": risk_level(score),

                "country": country,

                "isp": isp,

                "asn": asn,

                "asn_name": asn_name,

                "asn_category": asn_category,

                "asn_region": asn_region,

                "type": classify_endpoint(info)
            }

        except Exception:

            return {

                "ip": ip,

                "score": 50,

                "level": "MEDIUM",

                "country": "Unknown",

                "isp": "Unknown",

                "asn": "Unknown",

                "asn_name": "Unknown",

                "asn_category": "Unknown",

                "asn_region": "Unknown",

                "type": "UNKNOWN"
            }


if __name__ == "__main__":

    result = get_ip_info("8.8.8.8")

    print(result)