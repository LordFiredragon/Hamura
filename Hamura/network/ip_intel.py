import requests


class IPIntel:

    @staticmethod
    def lookup(ip):

        if not ip:
            return None

        try:

            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            )

            if response.status_code != 200:
                return None

            try:
                data = response.json()

            except Exception:
                return None

            if data["status"] != "success":
                return None

            return {
                "ip": ip,
                "country": data.get("country", "Unknown"),
                "region": data.get("regionName", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "asn": data.get("as", "Unknown")
            }

        except Exception as e:
            print("IP Lookup Error:", e)
            return None