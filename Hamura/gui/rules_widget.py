from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QHeaderView,
    QMenu,
    QMessageBox
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from security.firewall import Firewall
from database.database import Database


class RulesWidget(QWidget):

    def __init__(self):

        super().__init__()

        self.db = Database()

        layout = QVBoxLayout()

        self.table = QTableWidget()

        self.table.setColumnCount(4)

        self.table.setHorizontalHeaderLabels([
            "Type",
            "Target",
            "Action",
            "Created"
        ])
        self.table.setContextMenuPolicy(
            Qt.CustomContextMenu
        )

        self.table.customContextMenuRequested.connect(
            self.show_context_menu
        )

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        layout.addWidget(self.table)

        self.setLayout(layout)

        self.refresh()

    def refresh(self):

        rules = self.db.get_rules()

        self.table.setRowCount(
            len(rules)
        )

        for row, rule in enumerate(rules):

            type_item = QTableWidgetItem(
                str(rule["target_type"])
            )

            if rule["target_type"] == "APPLICATION":

                type_item.setBackground(
                    QColor(70, 120, 220)
                )

            elif rule["target_type"] == "IP":

                type_item.setBackground(
                    QColor(220, 150, 50)
                )

            self.table.setItem(
                row,
                0,
                type_item
            )

            self.table.setItem(
                row,
                1,
                QTableWidgetItem(
                    str(rule["target_value"])
                )
            )

            action_item = QTableWidgetItem(
                str(rule["action"])
            )

            action = str(rule["action"])

            if action == "BLOCK":

                action_item.setBackground(
                    QColor(220, 50, 50)
                )

            elif action == "ALLOW":

                action_item.setBackground(
                    QColor(50, 200, 50)
                )

            self.table.setItem(
                row,
                2,
                action_item
            )

            self.table.setItem(
                row,
                3,
                QTableWidgetItem(
                    str(rule["created_at"])
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

        rule_type = self.table.item(
            row,
            0
        ).text()

        target = self.table.item(
            row,
            1
        ).text()

        action = self.table.item(
            row,
            2
        ).text()

        menu = QMenu()

        allow_action = menu.addAction(
            "Allow"
        )

        block_action = menu.addAction(
            "Block"
        )

        selected = menu.exec_(
            self.table.viewport().mapToGlobal(
                position
            )
        )

        if selected == allow_action:

            self.allow_target(
                rule_type,
                target
            )

        elif selected == block_action:

            self.block_target(
                rule_type,
                target
            )

    def allow_target(
            self,
            rule_type,
            target):

        if rule_type == "IP":

            Firewall.unblock_ip(
                target
            )

        elif rule_type == "APPLICATION":

            self.db.add_application_rule(
                target,
                "ALLOW"
            )

        self.db.add_rule(
            rule_type,
            target,
            "ALLOW"
        )

        QMessageBox.information(
            self,
            "Hamura",
            f"{target} allowed."
        )

    def block_target(
            self,
            rule_type,
            target):

        if rule_type == "IP":

            Firewall.block_ip(
                target
            )

        elif rule_type == "APPLICATION":

            self.db.add_application_rule(
                target,
                "BLOCK"
            )

        self.db.add_rule(
            rule_type,
            target,
            "BLOCK"
        )

        QMessageBox.information(
            self,
            "Hamura",
            f"{target} blocked."
        )