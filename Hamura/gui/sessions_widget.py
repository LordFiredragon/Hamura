from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMenu
)
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QAbstractItemView
from PyQt5.QtWidgets import QMessageBox
from PyQt5.QtWidgets import QCheckBox
from database.database import Database
from security.firewall import Firewall


class SessionsWidget(QWidget):

    def __init__(self):

        super().__init__()

        self.db = Database()

        layout = QVBoxLayout()

        self.table = QTableWidget()
        self.active_only = QCheckBox(
            "Active Only"
        )

        self.active_only.setChecked(True)

        layout.addWidget(
            self.active_only
        )

        self.table.setColumnCount(7)

        self.table.setHorizontalHeaderLabels([
            "PID",
            "Process",
            "Remote IP",
            "Port",
            "Protocol",
            "First Seen",
            "Last Seen"
        ])
        self.table.setContextMenuPolicy(
            Qt.CustomContextMenu
        )

        self.table.customContextMenuRequested.connect(
            self.show_context_menu
        )

        self.table.setSelectionBehavior(
            QAbstractItemView.SelectItems
        )

        self.table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        self.table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        layout.addWidget(self.table)

        self.setLayout(layout)
        self.table.cellDoubleClicked.connect(
            self.show_ip_details
        )

        self.refresh_enabled = True

    def refresh(self):

        if not self.refresh_enabled:
            return

        if self.active_only.isChecked():

            sessions = (
                self.db.get_active_sessions()
            )

        else:

            sessions = (
                self.db.get_all_sessions()
            )

        self.table.setRowCount(
            len(sessions)
        )

        for row, session in enumerate(sessions):

            self.table.setItem(
                row, 0,
                QTableWidgetItem(
                    str(session["pid"])
                )
            )

            self.table.setItem(
                row, 1,
                QTableWidgetItem(
                    str(session["process_name"])
                )
            )

            self.table.setItem(
                row, 2,
                QTableWidgetItem(
                    str(session["remote_ip"])
                )
            )

            self.table.setItem(
                row, 3,
                QTableWidgetItem(
                    str(session["remote_port"])
                )
            )

            self.table.setItem(
                row, 4,
                QTableWidgetItem(
                    str(session["protocol"])
                )
            )

            self.table.setItem(
                row, 5,
                QTableWidgetItem(
                    str(session["first_seen"])
                )
            )

            self.table.setItem(
                row, 6,
                QTableWidgetItem(
                    str(session["last_seen"])
                )
            )

    def show_ip_details(self, row, column):

        ip_item = self.table.item(row, 2)

        if not ip_item:
            return

        ip = ip_item.text()

        info = self.db.get_ip_record(ip)

        if not info:
            return

        msg = QMessageBox(self)

        msg.setWindowTitle(
            "IP Intelligence"
        )

        msg.setText(
            f"""
        IP:
        {info['ip']}

        Country:
        {info['country']}

        ISP:
        {info['isp']}

        ASN:
        {info['asn']}

        Risk Score:
        {info['risk_score']}

        Risk Level:
        {info['risk_level']}
        """
        )

        block_btn = msg.addButton(
            "Block IP",
            QMessageBox.ActionRole
        )

        allow_btn = msg.addButton(
            "Allow IP",
            QMessageBox.ActionRole
        )

        close_btn = msg.addButton(
            QMessageBox.Close
        )

        msg.exec_()
        if msg.clickedButton() == block_btn:

            self.block_ip(
                info["ip"]
            )

        elif msg.clickedButton() == allow_btn:

            self.allow_ip(
                info["ip"]
            )

    def show_context_menu(self, position):

        item = self.table.itemAt(position)

        if not item:
            return

        # Only allow menu on IP column
        if item.column() != 2:
            return

        ip = item.text()

        self.refresh_enabled = False

        menu = QMenu()

        copy_action = menu.addAction(
            "Copy IP"
        )

        inspect_action = menu.addAction(
            "Inspect IP"
        )

        menu.addSeparator()

        block_action = menu.addAction(
            "Block IP"
        )

        allow_action = menu.addAction(
            "Allow IP"
        )

        action = menu.exec_(
            self.table.viewport().mapToGlobal(
                position
            )
        )

        self.refresh_enabled = True

        if action == copy_action:

            QApplication.clipboard().setText(
                ip
            )

        elif action == inspect_action:

            self.inspect_ip(ip)

        elif action == block_action:

            self.block_ip(ip)

        elif action == allow_action:

            self.allow_ip(ip)

    def inspect_ip(self, ip):

        info = self.db.get_ip_record(ip)

        if not info:
            QMessageBox.information(
                self,
                "Hamura",
                f"No intelligence found for {ip}"
            )

            return

        msg = QMessageBox(self)

        msg.setWindowTitle(
            "IP Intelligence"
        )

        msg.setText(
            f"""
                IP:
                {info['ip']}

                Country:
                {info['country']}

                ISP:
                {info['isp']}

                ASN:
                {info['asn']}

                Risk Score:
                {info['risk_score']}

                Risk Level:
                {info['risk_level']}
                """
        )

        block_btn = msg.addButton(
            "Block IP",
            QMessageBox.ActionRole
        )

        allow_btn = msg.addButton(
            "Allow IP",
            QMessageBox.ActionRole
        )

        close_btn = msg.addButton(
            QMessageBox.Close
        )

        msg.exec_()
        if msg.clickedButton() == block_btn:

            self.block_ip(
                info["ip"]
            )

        elif msg.clickedButton() == allow_btn:

            self.allow_ip(
                info["ip"]
            )

    def block_ip(self, ip):

        success = Firewall.block_ip(ip)

        if success:

            self.db.add_rule(
                "IP",
                ip,
                "BLOCK"
            )

            QMessageBox.information(
                self,
                "Hamura",
                f"{ip} blocked."
            )

        else:

            QMessageBox.warning(
                self,
                "Hamura",
                f"Failed to block {ip}"
            )

    def allow_ip(self, ip):

        success = Firewall.unblock_ip(ip)

        if success:

            self.db.add_rule(
                "IP",
                ip,
                "ALLOW"
            )

            QMessageBox.information(
                self,
                "Hamura",
                f"{ip} allowed."
            )

        else:

            QMessageBox.warning(
                self,
                "Hamura",
                f"Failed to allow {ip}"
            )
