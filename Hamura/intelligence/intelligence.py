import requests
from database.database import Database

db = Database()

class Intelligence:

    def __init__(self):
        self.timeout = 5

    def lookup_ip(self, ip):

        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=self.timeout
            )

            data = response.json()

            if data["status"] != "success":
                return None

            return {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "asn": data.get("as", "Unknown")
            }

        except Exception as e:
            print("Lookup Error:", e)
            return None

    def calculate_risk(self, info):

        score = 0

        isp = info.get("isp", "").lower()

        if "hosting" in isp:
            score += 15

        if "cloud" in isp:
            score += 10

        if "vpn" in isp:
            score += 25

        return min(score, 100)

    def get_reputation(self, ip):

        existing = db.get_ip_record(ip)

        if existing:
            print(f"[CACHE] {ip}")

            return existing

        print(f"[LOOKUP] {ip}")

        data = self.lookup_ip(ip)

        if not data:
            return None

        score = self.calculate_risk(data)

        result = {
            "ip": ip,
            "country": data.get("country"),
            "isp": data.get("isp"),
            "asn": data.get("as"),
            "risk_score": score
        }

        db.save_ip_reputation(
            ip,
            result["country"],
            result["isp"],
            result["asn"],
            result["risk_score"]
        )

        return result

if __name__ == "__main__":

    intel = Intelligence()

    result = intel.get_reputation("8.8.8.8")

    print(result)