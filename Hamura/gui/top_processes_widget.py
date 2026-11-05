from PyQt5.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView
)
from PyQt5.QtWidgets import (
    QMenu,
    QMessageBox,
    QApplication
)
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAbstractItemView
from database.database import Database


class TopProcessesWidget(QWidget):

    def __init__(self):

        super().__init__()

        self.db = Database()

        layout = QVBoxLayout()

        self.table = QTableWidget()
        self.table.setContextMenuPolicy(
            Qt.CustomContextMenu
        )

        self.table.customContextMenuRequested.connect(
            self.show_context_menu
        )

        self.table.setColumnCount(2)

        self.table.setHorizontalHeaderLabels([
            "Process",
            "Connections"
        ])

        self.table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.table.horizontalHeader().setSectionResizeMode(
            QHeaderView.Stretch
        )

        layout.addWidget(self.table)

        self.setLayout(layout)

        self.refresh()

    def refresh(self):

        processes = self.db.top_processes()

        self.table.setRowCount(
            len(processes)
        )

        for row, process in enumerate(processes):

            self.table.setItem(
                row,
                0,
                QTableWidgetItem(
                    str(process["process_name"])
                )
            )

            self.table.setItem(
                row,
                1,
                QTableWidgetItem(
                    str(process["connection_count"])
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

        process = self.table.item(
            row,
            0
        ).text()

        menu = QMenu()

        copy_action = menu.addAction(
            "Copy Process"
        )

        menu.addSeparator()

        block_action = menu.addAction(
            "Block Application"
        )

        allow_action = menu.addAction(
            "Allow Application"
        )

        action = menu.exec_(
            self.table.viewport().mapToGlobal(
                position
            )
        )

        if action == copy_action:

            QApplication.clipboard().setText(
                process
            )

        elif action == block_action:

            self.block_application(
                process
            )

        elif action == allow_action:

            self.allow_application(
                process
            )

    def block_application(
            self,
            process):

        self.db.add_application_rule(
            process,
            "BLOCK"
        )
        self.db.add_rule(
            "APPLICATION",
            process,
            "BLOCK"
        )

        QMessageBox.information(
            self,
            "Hamura",
            f"{process} blocked."
        )

    def allow_application(
            self,
            process):

        self.db.add_application_rule(
            process,
            "ALLOW"
        )
        self.db.add_rule(
            "APPLICATION",
            process,
            "ALLOW"
        )

        QMessageBox.information(
            self,
            "Hamura",
            f"{process} allowed."
        )
