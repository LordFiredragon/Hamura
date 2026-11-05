from PyQt5.QtCore import QThread
import ipaddress
import time
from network.ip_intel import IPIntel
from security.threat_intel import ThreatIntel
from network.monitor import ConnectionMonitor
from database.database import Database

db = Database()


class MonitorWorker(QThread):

    def run(self):

        db = Database()

        monitor = ConnectionMonitor()

        while True:
            blocked_apps_seen = set()
            connections = monitor.get_connections()
            print(
                "Connections found:",
                len(connections)
            )

            for conn in connections:
                process_name = conn["process"]
                remote_ip = conn["remote_ip"]
                rule = db.get_application_rule(
                    process_name
                )

                if (
                        rule
                        and
                        rule["action"] == "BLOCK"
                ):

                    if process_name not in blocked_apps_seen:
                        blocked_apps_seen.add(
                            process_name
                        )

                        db.create_alert(
                            "HIGH",
                            "Blocked Application",
                            f"{process_name} attempted network access.",
                            conn["remote_ip"],
                            process_name
                        )

                if not remote_ip:
                    continue

                db.update_session(
                    conn["pid"],
                    conn["process"],
                    remote_ip,
                    conn["remote_port"],
                    conn["protocol"]
                )

                try:

                    ip_obj = ipaddress.ip_address(
                        remote_ip
                    )

                    if (
                            ip_obj.is_private
                            or ip_obj.is_loopback
                    ):
                        continue

                except Exception:
                    continue

                cached = db.get_ip_info(remote_ip)

                if not cached:

                    intel = IPIntel.lookup(remote_ip)

                    if intel:

                        db.save_ip_reputation(
                            intel.get("ip", remote_ip),
                            intel.get("country", "Unknown"),
                            intel.get("isp", "Unknown"),
                            intel.get("asn", "Unknown")
                        )

                    else:

                        print(
                            f"[IP LOOKUP FAILED] {remote_ip}"
                        )
                score_data = ThreatIntel.score_ip(
                    remote_ip
                )

                db.update_threat_score(
                    remote_ip,
                    score_data["score"],
                    score_data["level"]
                )

                if (
                        not cached
                        and
                        score_data.get("type") == "RESIDENTIAL"
                ):
                    db.create_alert(
                        "LOW",
                        "Residential Endpoint Detected",
                        f"{remote_ip} appears to be a consumer ISP endpoint.",
                        remote_ip,
                        conn["process"]
                    )

            db.save_connections(connections)

            time.sleep(2)