import ctypes
import os
import sys


from PyQt5.QtCore import QTimer

from PyQt5.QtWidgets import (
    QApplication,
    QLabel,
    QMainWindow,
    QTabWidget,
    QVBoxLayout,
    QWidget
)
from workers.monitor_worker import MonitorWorker
from gui.connections_widget import ConnectionsWidget
from gui.sessions_widget import SessionsWidget
from gui.top_processes_widget import TopProcessesWidget
from gui.threats_widget import ThreatsWidget
from gui.alerts_widget import AlertsWidget
from gui.rules_widget import RulesWidget
from gui.chat_widget import ChatWidget
from database.database import Database
from network.traffic_monitor import TrafficMonitor


def resource_path(relative_path):

    try:
        base_path = sys._MEIPASS

    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(
        base_path,
        relative_path
    )

db = Database()

class HamuraWindow(QMainWindow):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Hamura Security AI | Lord Firedragon")
        self.resize(1400, 850)

        self.tabs = QTabWidget()

        self.dashboard_tab = QWidget()
        self.connections_tab = ConnectionsWidget()
        self.sessions_tab = SessionsWidget()
        self.processes_tab = TopProcessesWidget()
        self.threats_tab = ThreatsWidget()
        self.alerts_tab = AlertsWidget()
        self.rules_tab = RulesWidget()
        self.chat_tab = ChatWidget()

        self.tabs.addTab(
            self.dashboard_tab,
            "Dashboard"
        )

        self.tabs.addTab(
            self.connections_tab,
            "Connections"
        )

        self.tabs.addTab(
            self.sessions_tab,
            "Sessions"
        )

        self.tabs.addTab(
            self.processes_tab,
            "Processes"
        )

        self.tabs.addTab(
            self.threats_tab,
            "Threats"
        )

        self.tabs.addTab(
            self.alerts_tab,
            "Alerts"
        )

        self.tabs.addTab(
            self.rules_tab,
            "Rules"
        )

        self.tabs.addTab(
            self.chat_tab,
            "Chat"
        )

        self.setup_dashboard()

        self.setCentralWidget(self.tabs)
        self.monitor_worker = MonitorWorker()
        self.traffic = TrafficMonitor()
        self.monitor_worker.start()

        self.timer = QTimer()

        self.timer.timeout.connect(
            self.refresh_dashboard
        )

        self.timer.start(1000)

    def setup_dashboard(self):

        layout = QVBoxLayout()

        title = QLabel("HAMURA")
        title.setStyleSheet(
            """
            font-size:28px;
            font-weight:bold;
            color:#cc3300;
            """
        )

        self.download_label = QLabel(
            "Download: 0 KB/s"
        )

        self.upload_label = QLabel(
            "Upload: 0 KB/s"
        )

        self.connection_label = QLabel(
            "Connections: 0"
        )

        self.alert_label = QLabel(
            "Alerts: 0"
        )

        self.session_label = QLabel(
            "Sessions: 0"
        )

        self.threat_label = QLabel(
            "Threats: 0"
        )

        self.process_label = QLabel(
            "Processes: 0"
        )

        self.top_process_label = QLabel(
            "Top Process: None"
        )

        layout.addWidget(title)

        layout.addWidget(
            self.session_label
        )

        layout.addWidget(
            self.threat_label
        )

        layout.addWidget(
            self.process_label
        )

        layout.addWidget(
            self.top_process_label
        )

        layout.addWidget(
            self.download_label
        )

        layout.addWidget(
            self.upload_label
        )

        layout.addWidget(
            self.connection_label
        )

        layout.addWidget(
            self.alert_label
        )

        layout.addStretch()

        self.dashboard_tab.setLayout(
            layout
        )

    def refresh_dashboard(self):

        self.connections_tab.refresh()
        self.sessions_tab.refresh()
        self.processes_tab.refresh()
        self.threats_tab.refresh()
        self.alerts_tab.refresh()
        self.rules_tab.refresh()

        sessions = db.get_session_count()

        threats = db.get_high_risk_count()

        processes = db.get_process_count()

        try:

            traffic = self.traffic.get_speed()

            upload = (
                    traffic["upload"] / 1024
            )

            download = (
                    traffic["download"] / 1024
            )

            self.upload_label.setText(
                f"Upload: "
                f"{upload:.2f} KB/s"
            )

            self.download_label.setText(
                f"Download: "
                f"{download:.2f} KB/s"
            )

            self.session_label.setText(
                f"Sessions: {sessions}"
            )

            self.threat_label.setText(
                f"Threats: {threats}"
            )

            self.process_label.setText(
                f"Processes: {processes}"
            )

            top = db.get_top_process()

            if top:
                self.top_process_label.setText(
                    f"Top Process: "
                    f"{top['process_name']}"
                )

            recent_connections = (
                db.get_recent_connections(200)
            )

            alerts = db.get_alert_count()

            self.connection_label.setText(
                f"Connections: "
                f"{len(recent_connections)}"
            )

            self.alert_label.setText(
                f"Alerts: "
                f"{alerts}"
            )

        except Exception as e:

            print(e)

def is_admin():

    try:
        return ctypes.windll.shell32.IsUserAnAdmin()

    except Exception:
        return False

if __name__ == "__main__":
    try:
        if not is_admin():
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                " ".join(sys.argv),
                None,
                1
            )

            sys.exit()

        app = QApplication(sys.argv)

        window = HamuraWindow()
        window.show()

        sys.exit(app.exec_())


    except Exception as e:
        import traceback
        traceback.print_exc()
        input(

            "\nPress Enter to exit..."

        )