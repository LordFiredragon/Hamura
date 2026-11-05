import requests


def lookup_ip(ip):

    if not ip:
        return None

    try:

        url = f"http://ip-api.com/json/{ip}"

        response = requests.get(url, timeout=5)

        data = response.json()

        if data["status"] != "success":
            return None

        return {
            "country": data.get("country", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "isp": data.get("isp", ""),
            "asn": data.get("as", "")
        }

    except Exception as e:
        print("GeoIP Error:", e)
        return None


if __name__ == "__main__":

    result = lookup_ip("8.8.8.8")

    print(result)