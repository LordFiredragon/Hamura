from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMenu,
    QMessageBox,
)
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAbstractItemView
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QColor
from security.firewall import Firewall
from database.database import Database


class AlertsWidget(QWidget):

    def __init__(self):

        super().__init__()

        self.db = Database()

        layout = QVBoxLayout()

        self.table = QTableWidget()

        self.table.setColumnCount(6)

        self.table.setHorizontalHeaderLabels([
            "Time",
            "Severity",
            "Title",
            "IP",
            "Process",
            "Description"
        ])
        self.table.setContextMenuPolicy(
            Qt.CustomContextMenu
        )

        self.table.customContextMenuRequested.connect(
            self.show_context_menu
        )

        self.table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        self.table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.table.cellDoubleClicked.connect(
            self.show_ip_details
        )

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        layout.addWidget(self.table)

        self.setLayout(layout)

        self.refresh()

    def refresh(self):

        alerts = self.db.get_alerts()

        self.table.setRowCount(
            len(alerts)
        )

        for row, alert in enumerate(alerts):
            severity = str(alert["severity"])


            self.table.setItem(
                row, 0,
                QTableWidgetItem(
                    str(alert["timestamp"])
                )
            )

            severity_item = QTableWidgetItem(
                severity
            )

            if severity == "HIGH":

                severity_item.setBackground(
                    QColor(255, 100, 100)
                )

            elif severity == "MEDIUM":

                severity_item.setBackground(
                    QColor(255, 200, 100)
                )

            elif severity == "LOW":

                severity_item.setBackground(
                    QColor(255, 255, 150)
                )

            self.table.setItem(
                row,
                1,
                severity_item
            )

            self.table.setItem(
                row, 2,
                QTableWidgetItem(
                    str(alert["title"])
                )
            )

            self.table.setItem(
                row, 3,
                QTableWidgetItem(
                    str(alert["ip"])
                )
            )

            self.table.setItem(
                row, 4,
                QTableWidgetItem(
                    str(alert["process_name"])
                )
            )

            self.table.setItem(
                row, 5,
                QTableWidgetItem(
                    str(alert["description"])
                )
            )

    def show_context_menu(
            self,
            position):

        item = self.table.itemAt(
            position
        )

        if not item:
            return

        row = item.row()

        ip = self.table.item(
            row,
            3
        ).text()

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

    def show_ip_details(
            self,
            row,
            column):

        ip_item = self.table.item(
            row,
            3
        )

        if not ip_item:
            return

        self.inspect_ip(
            ip_item.text()
        )

    def copy_ip(self):

        row = self.table.currentRow()

        if row < 0:
            return

        ip = self.table.item(
            row,
            3  # IP column
        ).text()

        QApplication.clipboard().setText(
            ip
        )

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
