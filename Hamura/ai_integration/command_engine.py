from database.database import Database


class CommandEngine:

    def __init__(self):

        self.db = Database()

    def execute(self, text):

        text = text.lower()

        if "show threats" in text:

            threats = self.db.get_high_risk_ips()

            if not threats:
                return "No threats found."

            result = []

            for t in threats:

                result.append(
                    f"{t['ip']} "
                    f"(Risk {t['risk_score']})"
                )

            return "\n".join(result)

        elif "show alerts" in text:

            alerts = self.db.get_alerts()

            return f"{len(alerts)} alerts found."

        elif "show sessions" in text:

            return (
                f"Active Sessions: "
                f"{self.db.get_session_count()}"
            )

        return (
            "I don't understand that command."
        )