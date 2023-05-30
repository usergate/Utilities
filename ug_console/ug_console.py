#!/usr/bin/python3
#
# ug_view (simple SNMP viewer for NGFW UserGate), version 2.0.
#
# Copyright @ 2020-2022 UserGate Corporation. All rights reserved.
# Author: Aleksei Remnev <ran1024@yandex.ru>
# License: GPLv3
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, contact the site <https://www.gnu.org/licenses/>.
#
#--------------------------------------------------------------------------------------------------- 
#
import os, sys, json
import console_classes as cc
import config_style as cs
from PyQt6.QtGui import QFont, QPalette
from PyQt6.QtCore import QSize, Qt, QObject
from PyQt6.QtWidgets import QApplication, QMainWindow, QHBoxLayout, QVBoxLayout, QWidget, QTabWidget, QSplitter, QMenu, QFileDialog, QFrame


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._create_menu_bar()
        self._connect_actions()
        self.setWindowTitle("Консоль")

        self.container = QTabWidget()
        self.setCentralWidget(self.container)

    def _create_menu_bar(self):
        menu_bar = self.menuBar()
        file_menu = menu_bar.addMenu("Файл")
        self.open_config_action = file_menu.addAction("Загрузить конфигурацию")
        self.save_config_action = file_menu.addAction("Сохранить конфигурацию")
        file_menu.addSeparator()
        self.exit_action = file_menu.addAction("Выход", self.close)
        edit_menu = menu_bar.addMenu("Правка")
        help_menu = menu_bar.addMenu("Справка")

    def _connect_actions(self):
        # Menu actions
        self.open_config_action.triggered.connect(self.load_config_data)
        self.save_config_action.triggered.connect(self.save_config_data)

    def load_config_data(self):
        """
        Выбираем каталог с конфигурацией и читаем его. Фомируем set() с именами подкаталогов разделов.
        И вызываем функцию разблокировки соответствующего пункта дерева разделов MainTree::change_items_status()
        """
        base_path = QFileDialog.getExistingDirectory(self, directory="~")
        print("Загружаем конфигурацию:", base_path)
        _, _, name = base_path.rpartition("/")
        data = set()
        if not os.path.isdir(base_path):
            cs.message_alert(self, "", f"Не найден каталог с конфигурацией.\n{self.base_path} - не является каталогом.")
        else:
            try:
                for entry in os.scandir(base_path):
                    if entry.is_dir():
                        for sub_entry in os.scandir(entry.path):
                            if sub_entry.is_dir():
                                data.add(sub_entry.name)

                settings = QFrame()
                settings.setObjectName("main_frame")
                settings.setAccessibleDescription(base_path)
                settings.setContentsMargins(0, 0, 0, 0)
                settings_vbox = QVBoxLayout()
                settings_vbox.setContentsMargins(5, 0, 0, 0)
                settings.setLayout(settings_vbox)

                tree = cc.MainTree()
                tree.change_items_status(data)

                title_labels = cc.TitleLabels(base_path)

                splitter = QSplitter()
                splitter.addWidget(tree)
                splitter.addWidget(settings)
                hbox = QHBoxLayout()
                hbox.addWidget(splitter)

                vbox = QVBoxLayout()
                vbox.addWidget(title_labels)
                vbox.addWidget(splitter)

                main_widget = QWidget()
                main_widget.setLayout(vbox)

                self.container.addTab(main_widget, name)

            except FileNotFoundError as err:
                cs.message_alert(self, err, "Произошла ошибка загрузки конфигурации.")

    def save_config_data(self):
        print("Сохраняем конфигурацию...")


def main():
    app = QApplication([])
#    app.setStyle("Fusion")
#    app.setStyleSheet(cs.Style.app)
    window = MainWindow()
    window.resize(1300, 800)
    window.show()
    app.exec()

if __name__ == '__main__':
    main()
