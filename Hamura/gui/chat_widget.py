from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QTextEdit,
    QLineEdit,
    QPushButton,
    QListWidget,
    QLabel,
    QSplitter
)
from PyQt5.QtWidgets import QInputDialog
from PyQt5.QtCore import Qt

from database.database import Database


class ChatWidget(QWidget):

    def __init__(self):

        super().__init__()

        self.db = Database()

        main_layout = QVBoxLayout()

        splitter = QSplitter(
            Qt.Horizontal
        )

        # LEFT PANEL

        left_panel = QWidget()

        left_layout = QVBoxLayout()

        left_layout.addWidget(
            QLabel("Commands")
        )

        self.commands = QListWidget()

        self.commands.addItems([
            "system summary",
            "show connections",
            "show sessions",
            "show processes",
            "show threats",
            "show alerts",
            "show rules",
            "show blocked ips",
            "show blocked apps",
            "show application rules",
            "top process",
            "Inspect IP"
        ])

        left_layout.addWidget(
            self.commands
        )

        left_panel.setLayout(
            left_layout
        )

        # RIGHT PANEL

        right_panel = QWidget()

        right_layout = QVBoxLayout()

        self.output = QTextEdit()

        self.output.setReadOnly(True)

        self.output.append(
            "Hamura: Ready."
        )

        bottom = QHBoxLayout()

        self.input = QLineEdit()

        self.send_btn = QPushButton(
            "Send"
        )

        bottom.addWidget(
            self.input
        )

        bottom.addWidget(
            self.send_btn
        )

        right_layout.addWidget(
            self.output
        )

        right_layout.addLayout(
            bottom
        )

        right_panel.setLayout(
            right_layout
        )

        splitter.addWidget(
            left_panel
        )

        splitter.addWidget(
            right_panel
        )

        splitter.setSizes(
            [250, 900]
        )

        main_layout.addWidget(
            splitter
        )

        self.setLayout(
            main_layout
        )

        self.commands.itemClicked.connect(
            self.command_selected
        )

        self.commands.itemDoubleClicked.connect(
            self.command_execute
        )

        self.send_btn.clicked.connect(
            self.send_command
        )

        self.input.returnPressed.connect(
            self.send_command
        )

    def command_selected(
            self,
            item):

        self.input.setText(
            item.text()
        )

    def command_execute(
            self,
            item):

        self.input.setText(
            item.text()
        )

        self.send_command()

    def send_command(self):

        command = (
            self.input.text()
            .strip()
            .lower()
        )

        if not command:
            return

        self.output.append(
            f"\n> {command}"
        )

        self.handle_command(command)

        self.input.clear()

    def handle_command(
            self,
            command):
        if command == "inspect ip":

            ip, ok = QInputDialog.getText(
                self,
                "Inspect IP",
                "Enter IP Address:"
            )

            if not ok or not ip:
                return

            command = f"inspect ip {ip}"

        if command in [
            "system summary",
            "summary",
            "status"
        ]:

            self.output.append(
                "\nHamura:"
            )

            self.output.append(
                f"Connections: "
                f"{len(self.db.get_recent_connections(200))}"
            )

            self.output.append(
                f"Sessions: "
                f"{self.db.get_session_count()}"
            )

            self.output.append(
                f"Processes: "
                f"{self.db.get_process_count()}"
            )

            self.output.append(
                f"Threats: "
                f"{self.db.get_high_risk_count()}"
            )

            self.output.append(
                f"Alerts: "
                f"{self.db.get_alert_count()}"
            )

        elif command in ["show alerts" , "alerts"]:

            alerts = (
                self.db.get_alerts()
            )

            self.output.append(
                "\nHamura:"
            )

            for alert in alerts[:10]:

                self.output.append(
                    f"{alert['severity']} | "
                    f"{alert['ip']}"
                )

        elif command in ["show threats" , "threats"]:

            threats = (
                self.db.get_high_risk_ips()
            )

            self.output.append(
                "\nHamura:"
            )

            if not threats:

                self.output.append(
                    "No threats found."
                )

                return

            for threat in threats:

                self.output.append(
                    f"{threat['ip']} | "
                    f"Risk: "
                    f"{threat['risk_score']}"
                )

        elif command in ["show sessions" , "sessions"]:

            sessions = (
                self.db.get_active_sessions()
            )

            self.output.append(
                "\nHamura:"
            )

            self.output.append(
                f"Active Sessions: "
                f"{len(sessions)}"
            )

        elif command in ["show processes" , "processes"]:

            processes = (
                self.db.top_processes()
            )

            self.output.append(
                "\nHamura:"
            )

            for p in processes:

                self.output.append(
                    f"{p['process_name']} "
                    f"({p['connection_count']})"
                )

        elif command in ["show rules" , "rules"]:

            rules = (
                self.db.get_rules()
            )

            self.output.append(
                "\nHamura:"
            )

            for rule in rules:

                self.output.append(
                    f"{rule['action']} "
                    f"{rule['target_value']}"
                )

        elif command in ["top process" , "process"]:

            top = (
                self.db.get_top_process()
            )

            self.output.append(
                "\nHamura:"
            )

            if top:

                self.output.append(
                    f"{top['process_name']} "
                    f"({top['total']} connections)"
                )

        elif command in ["show connections" , "connections"]:

            connections = (
                self.db.get_recent_connections(20)
            )

            self.output.append(
                "\nHamura:"
            )

            self.output.append(
                f"Recent Connections: "
                f"{len(connections)}"
            )

        elif command.startswith("inspect ip"):

            parts = command.split()

            if len(parts) < 3:
                self.output.append(
                    "\nHamura:"
                )

                self.output.append(
                    "Usage: inspect ip <address>"
                )

                return

            ip = parts[2]

            record = (
                self.db.get_ip_record(ip)
            )

            self.output.append(
                "\nHamura:"
            )

            if not record:
                self.output.append(
                    f"No intelligence found for {ip}"
                )

                return

            self.output.append(
                f"IP: {record['ip']}"
            )

            self.output.append(
                f"Country: {record['country']}"
            )

            self.output.append(
                f"ISP: {record['isp']}"
            )

            self.output.append(
                f"ASN: {record['asn']}"
            )

            self.output.append(
                f"Risk Score: "
                f"{record['risk_score']}"
            )

            if "risk_level" in record.keys():
                self.output.append(
                    f"Risk Level: "
                    f"{record['risk_level']}"
                )

        elif command == "show application rules":

            rules = self.db.get_application_rules()

            self.output.append(
                "\nHamura:"
            )

            if not rules:
                self.output.append(
                    "No application rules."
                )

                return

            for rule in rules:
                self.output.append(
                    f"{rule['process_name']} : "
                    f"{rule['action']}"
                )

        elif command == "show blocked apps":

            rules = self.db.get_application_rules()

            self.output.append(
                "\nHamura:"
            )

            found = False

            for rule in rules:

                if rule["action"] == "BLOCK":
                    found = True

                    self.output.append(
                        rule["process_name"]
                    )

            if not found:
                self.output.append(
                    "No blocked applications."
                )

        elif command == "show blocked ips":

            blocked = self.db.get_blocked_ips()

            self.output.append(
                "\nHamura:"
            )

            if not blocked:
                self.output.append(
                    "No blocked IPs."
                )

                return

            for entry in blocked:
                self.output.append(
                    entry["target_value"]
                )

        else:

            self.output.append(
                "\nHamura:"
            )

            self.output.append(
                "Threat analysis complete."
            )


