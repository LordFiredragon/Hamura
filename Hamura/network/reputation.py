import requests


def lookup_ip(ip):
    try:

        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )

        data = r.json()

        return {
            "country": data.get("country"),
            "isp": data.get("isp"),
            "asn": data.get("asn")
        }

    except Exception as e:
        print(e)
        return None


if __name__ == "__main__":

    print(lookup_ip("8.8.8.8"))