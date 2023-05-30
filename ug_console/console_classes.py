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
import os, json
from PyQt6.QtGui import *
#from PyQt6.QtCore import *
#from PyQt6.QtGui import QFont
from PyQt6.QtCore import Qt, QObject, pyqtSignal
from PyQt6.QtWidgets import (QTreeWidget, QTreeWidgetItem, QSizePolicy, QLabel, QWidget, QPushButton, QFrame,
                             QGroupBox, QFormLayout, QVBoxLayout, QGridLayout, QHBoxLayout, QScrollArea, QDialog,
                             QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView, QSplitter, QDialogButtonBox
                             )
import config_style as cs
import dialog_classes as dc


class MainTree(QTreeWidget):
    itemSelected = pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.setStyleSheet(cs.Style.MainTree)

        self.compliances = {
            "UserGate": "UserGate",
            "GeneralSettings": "Настройки",
            "DeviceManagement": "Управление устройсвом",
            "Administrators": "Администраторы",
            "Certificates": "Сертификаты",
            "Network": "Сеть",
            "Zones": "Зоны",
            "Interfaces": "Интерфейсы",
            "Gateways": "Шлюзы",
            "DHCP": "DHCP",
            "DNS": "DNS",
            "VRF": "Виртуальные маршрутизаторы",
            "WCCP": "WCCP",
            "UsersAndDevices": "Пользователи и устройства",
            "Groups": "Группы",
            "Users": "Пользователи",
            "AuthServers": "Серверы аутентификации",
            "AuthProfiles": "Профили аутентификации",
            "CaptivePortal": "Captive-портал",
            "CaptiveProfiles": "Captive-профили",
            "TerminalServers": "Терминальные серверы",
            "MFAProfiles": "Профили MFA",
            "BYODPolicies": "Политики BYOD",
            "BYODDevices": "Устройства BYOD",
            "NetworkPolicies": "Политики сети",
            "Firewall": "Межсетевой экран",
            "NATandRouting": "NAT и маршрутизация",
            "LoadBalancing": "Балансировка нагрузки",
            "TrafficShaping": "Пропускная способность",
            "SecurityPolicies": "Политики безопасности",
            "ContentFiltering": "Фильтрация контента",
            "SafeBrowsing": "Веб-безопасность",
            "SSLInspection": "Инспектирование SSL",
            "SSHInspection": "Инспектирование SSH",
            "IntrusionPrevention": "СОВ",
            "SCADARules": "Правила АСУ ТП",
            "Scenarios": "Сценарии",
            "MailSecurity": "Защита почтового трафика",
            "ICAPRules": "ICAP-правила",
            "ICAPServers": "ICAP-серверы",
            "DoSRules": "Правила защиты DoS",
            "DoSProfiles": "Профили DoS",
            "GlobalPortal": "Глобальный портал",
            "WebPortal": "Веб-портал",
            "ReverseProxyRules": "Правила reverse-прокси",
            "ReverseProxyServers": "Серверы reverse-прокси",
            "VPN": "VPN",
            "ServerRules": "Серверные правила",
            "ClientRules": "Клиентские правила",
            "VPNNetworks": "Сети VPN",
            "SecurityProfiles": "Профили безопасности VPN",
            "Libraries": "Библиотеки",
            "Morphology": "Морфология",
            "Services": "Сервисы",
            "IPAddresses": "IP-адреса",
            "Useragents": "Useragent браузеров",
            "ContentTypes": "Типы контента",
            "URLLists": "Списки URL",
            "TimeSets": "Календари",
            "BandwidthPools": "Полосы пропускания",
            "SCADAProfiles": "Профили АСУ ТП",
            "ResponcePages": "Шаблоны страниц",
            "URLCategories": "Категории URL",
            "OverURLCategories": "Изменённые категории URL",
            "Applications": "Приложения",
            "Emails": "Почтовые адреса",
            "Phones": "Номера телефонов",
            "IPSProfiles": "Профили СОВ",
            "NotificationProfiles": "Профили оповещений",
            "NetflowProfiles": "Профили netflow",
            "SSLProfiles": "Профили SSL",
        }
        
        self.over_compliances = {v: k for k, v in self.compliances.items()}

        data = {
            "UserGate": ["Настройки", "Управление устройсвом", "Администраторы", "Сертификаты"],
            "Сеть": ["Зоны", "Интерфейсы", "Шлюзы", "DHCP", "DNS", "Виртуальные маршрутизаторы", "WCCP"],
            "Пользователи и устройства": ["Группы", "Пользователи", "Серверы аутентификации", "Профили аутентификации", "Captive-портал",
                                          "Captive-профили", "Терминальные серверы", "Профили MFA", "Политики BYOD", "Устройства BYOD"],
            "Политики сети": ["Межсетевой экран", "NAT и маршрутизация", "Балансировка нагрузки", "Пропускная способность"],
            "Политики безопасности": ["Фильтрация контента", "Веб-безопасность", "Инспектирование SSL", "Инспектирование SSH", "СОВ",
                                      "Правила АСУ ТП", "Сценарии", "Защита почтового трафика", "ICAP-правила", "ICAP-серверы",
                                      "Правила защиты DoS", "Профили DoS"],
            "Глобальный портал": ["Веб-портал", "Правила reverse-прокси", "Серверы reverse-прокси"],
            "VPN": ["Серверные правила", "Клиентские правила", "Сети VPN", "Профили безопасности VPN"],
            "Библиотеки": ["Морфология", "Сервисы", "IP-адреса", "Useragent браузеров", "Типы контента", "Списки URL", "Календари",
                           "Полосы пропускания", "Профили АСУ ТП", "Шаблоны страниц", "Категории URL", "Изменённые категории URL",
                           "Приложения", "Почтовые адреса", "Номера телефонов", "Профили СОВ", "Профили оповещений", "Профили netflow",
                           "Профили SSL"],
        }

        tree_head_font = QFont("Noto Sans", pointSize=10, weight=700)

        self.setHeaderHidden(True)
        self.setIndentation(10)

        items = []
        for key, values in data.items():
            item = QTreeWidgetItem([key])
            item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            item.setForeground(0, Qt.GlobalColor.darkBlue)
            item.setFont(0, tree_head_font)
            for value in values:
                child = QTreeWidgetItem([value])
                child.setDisabled(True)
                item.addChild(child)
            items.append(item)
        self.insertTopLevelItems(0, items)
        self.expandAll()
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Expanding)
        
        self.itemSelectionChanged.connect(self.select_item)

    def change_items_status(self, data):
        for name in data:
            if name in self.compliances:
                item = self.findItems(self.compliances[name], Qt.MatchFlag.MatchRecursive)[0]
                item.setDisabled(False)

    def select_item(self):
        """
        При выборе раздела в дереве, получаем выбранный раздел и его родителя. Строим путь к каталогу с конфигурацией данного раздела.
        Получаем относительный путь к конфигурации выделенного раздела. Строим полный путь и загружаем файлы конфигурации раздела.
        """
        if self.selectedItems():
            self.main_frame = self.parent().findChild(QObject, "main_frame")
            self.main_frame_vbox = self.main_frame.children()[0]
            base_path = self.main_frame.accessibleDescription()
            selected_item = self.selectedItems()[0]
            parent = selected_item.parent().text(0)
            selected_path = f"{self.over_compliances[parent]}/{self.over_compliances[selected_item.text(0)]}"
            path = f"{base_path}/{selected_path}"
            print(path)

            if not os.path.isdir(base_path):
                new_widget = AlertLabel(f"Не найден каталог с конфигурацией\n{base_path}")
            elif not os.path.isdir(path):
                new_widget = AlertLabel(f"Не найден каталог\n {self.path}\n с конфигурацией этого раздела.")
            elif selected_path == "UserGate/GeneralSettings":
                widget = GeneralSettings(base_path, selected_path)
                new_widget = MyScrollArea()
                new_widget.setWidget(widget)
            elif selected_path == "UserGate/Administrators":
                new_widget = Administrators(path)
            elif selected_path == "UserGate/Certificates":
                new_widget = Certificates(path)
            elif selected_path == "Network/Zones":
                new_widget = Zones(path)
            elif selected_path == "Network/Interfaces":
                new_widget = Interfaces(path)
            self._update_tab_settings(new_widget)

    def _update_tab_settings(self, new_widget):
        """
        Добавляем виджет раздела в main_frame если там пусто. Если нет, то удаляем существующий виджет и затем добавляем новый.
        """
        print("count: ", self.main_frame_vbox.count())
        if self.main_frame_vbox.count() == 0:
            self.main_frame_vbox.insertWidget(0, new_widget)
        else:
            old_widget = self.main_frame.findChild(QObject, "section_mainwidget")
            print(old_widget.parentWidget(), " --> ", old_widget)
            old_widget.deleteLater()
            self.main_frame_vbox.insertWidget(0, new_widget)


class TitleLabels(QFrame):
    def __init__(self, base_path):
        super().__init__()
        self.setObjectName("title_labels")
        self.setFixedHeight(25)
        self.setStyleSheet(cs.Style.Test)

        with open(f"{base_path}/general_values.json", "r") as fh:
            data = json.load(fh)
        label2 = QLabel(f"Версия: {data['version']}")
        label2.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label3 = QLabel(f"{base_path}  ")
        label3.setAlignment(Qt.AlignmentFlag.AlignRight)

        layout = QHBoxLayout()
        layout.addWidget(QLabel(f"  {data['node_name']}"))
        layout.addWidget(label2)
        layout.addWidget(label3)
        layout.setContentsMargins(0, 2, 0, 2)
        self.setLayout(layout)


class AlertLabel(QWidget):
    def __init__(self, text):
        super().__init__()
        self.setObjectName("section_mainwidget")
        label = QLabel(text)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setMargin(100)
        vbox = QVBoxLayout()
        vbox.addWidget(label)
        vbox.addStretch(2)
        self.setLayout(vbox)


class ColorLabel(QLabel):
    def __init__(self, value, color, name=None):
        super().__init__(value)
        self.color = color
        self.name = name
        if self.name:
            self.setObjectName(self.name)
        self.setStyleSheet(f"color: {self.color}")

    def enterEvent(self, e):
        if self.name:
            self.setStyleSheet(f"color: blue")
            self.setCursor(Qt.CursorShape.OpenHandCursor)
        e.accept()

    def leaveEvent(self, e):
        if self.name:
            self.setStyleSheet(f"color: {self.color}")
        e.accept()

    def mousePressEvent(self, e):
        if self.name and (e.button() & Qt.MouseButton.LeftButton):
            eval(f'dc.{self.name}(self.parent())()')
        e.accept()


class MyScrollArea(QScrollArea):
    def __init__(self):
        super().__init__()
        style = '''
            *   {
                    background-color: #fbfbfb;
                
                }
            QScrollArea QScrollBar:handle:hover {
                    background-color: darkgrey;
                }
        '''
        self.setObjectName("section_mainwidget")
        self.setContentsMargins(0, 0, 0, 0)
        self.setStyleSheet(style)
        self.setAutoFillBackground(True)
        self.setFrameShape(self.Shape.NoFrame)


class GeneralSettings(QWidget):
    def __init__(self, base_path, selected_path):
        super().__init__()
        self.base_path = base_path
        self.path = f"{base_path}/{selected_path}"
        self.setObjectName("GeneralSettings")
        self.setContentsMargins(0, 0, 0, 0)
        self.setStyleSheet(cs.Style.GroupBox)
        self._scandir()
        
        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(self.box_ui)
        vbox.addWidget(self.box_ntp)
        vbox.addLayout(self.hbox_proxy)
        vbox.addWidget(self.box_loganalyzer)
        vbox.addWidget(self.box_webportal)
        vbox.addWidget(self.box_pcap)
        vbox.addWidget(self.box_tracker)
        vbox.addWidget(self.box_mc)
        vbox.addWidget(self.box_updates_schedule)
        hbox = QHBoxLayout()
        hbox.setContentsMargins(0, 0, 0, 0)
        hbox.addLayout(vbox)
        hbox.addStretch(5)
        self.setLayout(hbox)

    def _scandir(self):
        file_names = []
        with os.scandir(self.path) as item:
            for entry in item:
                if not entry.name.startswith(".") and entry.is_file():
                    file_names.append(entry.name)
        if "config_settings_ui.json" in file_names:
            self._create_box_ui()
        if "config_ntp.json" in file_names:
            self._create_box_ntp()
        if "config_settings.json" in file_names:
            self._create_box_proxy()
        if "config_log_analyzer.json" in file_names:
            self._create_box_loganalyzer()
        if "config_proxy_portal.json" in file_names:
            self._create_box_webportal()
        if "config_pcap_settings.json" in file_names:
            self._create_box_pcap()
        if "config_event_tracker.json" in file_names:
            self._create_box_tracker()
        if "config_mc_agent.json" in file_names:
            self._create_box_mc()
        self._create_box_updates_schedule()

    def _create_box_ui(self):
        """
        Создаём GroupBox для области "Настройка интерфейса"
        config_file: config_settings_ui.json
        """
        self.box_ui = QGroupBox("Настройка интерфейса")

        with open(f"{self.path}/config_settings_ui.json", "r") as fh:
            data = json.load(fh)
        
        form = QFormLayout()
        form.addRow("Часовой пояс", cs.SelectLabel(data["ui_timezone"], cs.Color.NORM))
        form.addRow("Язык интерфейса по умолчанию", cs.SelectLabel(data["ui_language"], cs.Color.NORM))
        form.addRow("Режим аутентификации веб-консоли", cs.SelectLabel(data["webui_auth_mode"], cs.Color.NORM))
        form.addRow("Профиль SSL для веб-консоли", cs.SelectLabel(data["web_console_ssl_profile_id"], cs.Color.NORM))
        form.addRow("Профиль SSL для страниц блокировки/аутентификации", cs.SelectLabel(data["response_pages_ssl_profile_id"], cs.Color.NORM))
        form.setHorizontalSpacing(20)

        self.box_ui.setLayout(form)

    def _create_box_ntp(self):
        """
        Создаём GroupBox для области "Настройка времени сервера"
        config_file: config_ntp.json
        """
        self.box_ntp = QGroupBox("Настройка времени сервера")

        with open(f"{self.path}/config_ntp.json", "r") as fh:
            data = json.load(fh)
        
        data["ntp_enabled"] = "Включено" if data["ntp_enabled"] else "Отключено"
        try:
            value = data["ntp_servers"][0]
        except IndexError:
            value =  "Введите значение"
        primary_server = cs.SelectLabel(value, cs.Color.NORM)
        try:
            value = data["ntp_servers"][1]
        except IndexError:
            value =  "Введите значение"
        secondary_server = cs.SelectLabel(value, cs.Color.NORM)

        if data["ntp_synced"]:
            ntp_synced = cs.SelectLabel("Синхр. успешно", cs.Color.GREEN)
        else:
            ntp_synced = cs.SelectLabel("Ошибка", cs.Color.ALARM)

        layout = QGridLayout()
        layout.addWidget(cs.SelectLabel("Использовать NTP"), 0, 0)
        layout.addWidget(cs.SelectLabel(data["ntp_enabled"], cs.Color.NORM), 0, 1)
        layout.addWidget(ntp_synced, 0, 2)
        layout.addWidget(cs.SelectLabel("Основной NTP-сервер"), 1, 0)
        layout.addWidget(primary_server, 1, 1)
        layout.addWidget(cs.SelectLabel("Запасной NTP-сервер"), 2, 0)
        layout.addWidget(secondary_server, 2, 1)
        layout.addWidget(cs.SelectLabel("Время на сервере (UTC)"), 3, 0)
        layout.addWidget(cs.SelectLabel(data["utc_time"], cs.Color.NORM), 3, 1)

        self.box_ntp.setLayout(layout)

    def _create_box_proxy(self):
        """
        Создаём GroupBox для области "Настройка времени сервера"
        config_files: config_proxy_port.jsaon, config_settings.json
        """
        with open(f"{self.path}/config_proxy_port.json", "r") as fh:
            proxy_port = fh.read().strip()

        with open(f"{self.path}/config_snmp_engine_id.json", "r") as fh:
            snmp_engine = json.load(fh)

        with open(f"{self.path}/config_settings.json", "r") as fh:
            data = json.load(fh)

        self.box_proxy = QGroupBox("Модули")
        data["ftp_proxy_enabled"] = "Включено" if data["ftp_proxy_enabled"] else "Отключено"
        layout = QFormLayout()
        layout.addRow("HTTP(S)-прокси порт", cs.SelectLabel(str(proxy_port), cs.Color.NORM))
        layout.addRow("Домен Auth captive-портала", cs.SelectLabel(data['auth_captive'], cs.Color.NORM))
        layout.addRow("Домен Logout captive-портала", cs.SelectLabel(data['logout_captive'], cs.Color.NORM))
        layout.addRow("Домен страницы блокировки", cs.SelectLabel(data['block_page_domain'], cs.Color.NORM))
        layout.addRow("FTP поверх HTTP", cs.SelectLabel(data['ftp_proxy_enabled'], cs.Color.NORM))
        layout.addRow("FTP поверх HTTP домен", cs.SelectLabel(data['ftpclient_captive'], cs.Color.NORM))
        layout.addRow("SNMP Engine ID", cs.SelectLabel(f"{snmp_engine['type']}: {snmp_engine['data']} - {snmp_engine['length']}", cs.Color.NORM))
        layout.setHorizontalSpacing(20)
        self.box_proxy.setLayout(layout)

        self.box_cache = QGroupBox("Настройки кэширования HTTP")
        layout = QFormLayout()
        layout.addRow("Режим кэширования", cs.SelectLabel(data['http_cache_mode'], cs.Color.NORM))
        layout.addRow("Исключения кэширования", ColorLabel("Исключения", cs.Color.NORM, name="ProxyExceptions"))
        layout.addRow("Максимальный размер объекта (МБ)", cs.SelectLabel(str(data['http_cache_docsize_max']), cs.Color.NORM))
        layout.addRow("Размер RAM-кэша (МБ)", cs.SelectLabel(str(data['http_cache_precache_size']), cs.Color.NORM))
        layout.setHorizontalSpacing(20)
        self.box_cache.setLayout(layout)

        self.hbox_proxy = QHBoxLayout()
        self.hbox_proxy.addWidget(self.box_proxy)
        self.hbox_proxy.addWidget(self.box_cache)
        
#        SelectableLine.returnPressed.connect(self.test("test"))

        
    def _create_box_loganalyzer(self):
        """
        Создаём GroupBox для области "Log Analyzer"
        config_file: config_log_analyzer.json, global_values.json
        """
        self.box_loganalyzer = QGroupBox("Log Analyzer")

        with open(f"{self.path}/config_log_analyzer.json", "r") as fh:
            data = json.load(fh)
        with open(f"{self.base_path}/general_values.json", "r") as fh:
            data1 = json.load(fh)
        
        color = cs.Color.GREEN if data["state"] == "ready" else cs.Color.ALARM
        alarms = ""
        for k, v in data["alarms"].items():
            alarms = alarms + f"{k}: {v} "
        
        layout = QGridLayout()
        layout.addWidget(cs.SelectLabel("Log Analyzer"), 0, 0)
        layout.addWidget(cs.SelectLabel(data["server_address"], cs.Color.NORM), 0, 1)
        layout.addWidget(cs.SelectLabel(data["state"], color), 0, 2)
        layout.addWidget(cs.SelectLabel("Версия Log Analyzer"), 1, 0)
        layout.addWidget(cs.SelectLabel(data["version"], cs.Color.NORM), 1, 1)
        layout.addWidget(cs.SelectLabel(alarms, cs.Color.ALARM), 1, 2)
        layout.addWidget(cs.SelectLabel("Версия устройства"), 2, 0)
        layout.addWidget(cs.SelectLabel(data1["version"], cs.Color.NORM), 2, 1)
        self.box_loganalyzer.setLayout(layout)

    def _create_box_webportal(self):
        """
        Создаём GroupBox для области "Веб-портал"
        config_file: config_proxy_portal.json
        """
        self.box_webportal = QGroupBox("Веб-портал")

        with open(f"{self.path}/config_proxy_portal.json", "r") as fh:
            data = json.load(fh)
       
        status = cs.SelectLabel("Включено", cs.Color.GREEN) if data["enabled"] else cs.SelectLabel("Отключено", cs.Color.ORANGE)
        
        layout = QGridLayout()
        layout.addWidget(cs.SelectLabel("Адрес Веб-портала"), 0, 0)
        layout.addWidget(ColorLabel(f'{data["host"]}:{data["port"]}', cs.Color.NORM, name="ProxyPortal"), 0, 1)
        layout.addWidget(status, 0, 2)

        self.box_webportal.setLayout(layout)

    def _create_box_pcap(self):
        """
        Создаём GroupBox для области "Настройка PCAP"
        config_file: config_pcap_settings.json
        """
        self.box_pcap = QGroupBox("Настройка PCAP")

        with open(f"{self.path}/config_pcap_settings.json", "r") as fh:
            data = json.load(fh)
        
        layout = QGridLayout()
        layout.addWidget(cs.SelectLabel("Захват пакетов"), 0, 0)
        layout.addWidget(ColorLabel(data["mode"], cs.Color.NORM), 0, 1, 1, 2)

        self.box_pcap.setLayout(layout)

    def _create_box_tracker(self):
        """
        Создаём GroupBox для области "Учёт изменений"
        config_file: config_event_tracker.json
        """
        self.box_tracker = QGroupBox("Учёт изменений")

        with open(f"{self.path}/config_event_tracker.json", "r") as fh:
            data = json.load(fh)
       
        status = cs.SelectLabel("Включено", cs.Color.GREEN) if data["enabled"] else cs.SelectLabel("Отключено", cs.Color.ORANGE)
        
        layout = QGridLayout()
        layout.addWidget(cs.SelectLabel("Учёт изменений"), 0, 0)
        layout.addWidget(ColorLabel("Настроить", cs.Color.NORM, name="EventTracker"), 0, 1)
        layout.addWidget(status, 0, 2)

        self.box_tracker.setLayout(layout)

    def _create_box_mc(self):
        """
        Создаём GroupBox для области "Агент UerGate Management Center"
        config_file: config_mc_agent.json
        """
        self.box_mc = QGroupBox("Агент UerGate Management Center")

        with open(f"{self.path}/config_mc_agent.json", "r") as fh:
            data = json.load(fh)
       
        if data["is_configured"]:
            status = cs.SelectLabel("Работает", cs.Color.GREEN) if data["enabled"] else cs.SelectLabel("Ошибка подключения", cs.Color.ALARM)
            agent_str = ColorLabel(data["address"], cs.Color.NORM, name="MCAgent")
        else:
            status = cs.SelectLabel("Не настроено", cs.Color.ORANGE)
            agent_str = ColorLabel("Настроить", cs.Color.NORM)
        
        layout = QGridLayout()
        layout.addWidget(cs.SelectLabel("Настройка агента"), 0, 0)
        layout.addWidget(agent_str, 0, 1)
        layout.addWidget(status, 0, 2)

        self.box_mc.setLayout(layout)

    def _create_box_updates_schedule(self):
        """
        Создаём GroupBox для области "Расписание скачивания обновлений"
        config_file: config_updates_schedule.json
        """
        self.box_updates_schedule = QGroupBox("Расписание скачивания обновлений")

        layout = QGridLayout()
        layout.addWidget(cs.SelectLabel("Расписание скачивания обновлений"), 0, 0)
        layout.addWidget(ColorLabel("Настроить", cs.Color.NORM), 0, 1)
        layout.addWidget(ColorLabel("Проверка обновлений", cs.Color.NORM), 0, 2)

        self.box_updates_schedule.setLayout(layout)


class Administrators(QWidget):
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.setObjectName("section_mainwidget")
        self.setContentsMargins(0, 0, 0, 0)
        self.setStyleSheet(cs.Style.GroupBox)
        self._create_box_admins()
        self._create_box_profiles()
        self._create_box_sessions_admins()

        splitter1 = QSplitter(Qt.Orientation.Horizontal)
        splitter1.addWidget(self.box_admins)
        splitter1.addWidget(self.box_profiles)

        splitter2 = QSplitter(Qt.Orientation.Vertical)
        splitter2.addWidget(splitter1)
        splitter2.addWidget(self.box_sessions_admins)
        splitter2.setStretchFactor(0, 5)
        splitter2.setStretchFactor(1, 1)
        
        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(splitter2)
        self.setLayout(vbox)

    def _create_box_admins(self):
        """
        Создаём GroupBox для области "Администраторы"
        config_file: admins_list.json.json
        """
        self.box_admins = QGroupBox("Администраторы")

        button_box = QDialogButtonBox(parent=self.box_admins)
        button_edit = button_box.addButton("Редактировать", QDialogButtonBox.ButtonRole.ActionRole)
        button_act = button_box.addButton("Настроить", QDialogButtonBox.ButtonRole.ActionRole)
        button_edit.setObjectName("admin_edit")
        button_act.setObjectName("admin_act")
        button_box.clicked.connect(self.selected_buttons)

        self.tree_1 = cs.MyTree(["Имя", "Описание", "Профиль администратора"], style=cs.Style.ListTree)
        try:
            with open(f"{self.path}/admins_list.json", "r") as fh:
                data = json.load(fh)
        except Exception as err:
            cs.message_alert(self, err, f"Проблема с файлом:\n {self.path}/admins_list.json")
        else:
            items = []
            for value in data:
                profile = value['profile_id'] if value['profile_id'] != -1 else "Корневой профиль"
                item = QTreeWidgetItem([value['login'], value['description'], profile])
                item.setFlags(Qt.ItemFlag.ItemIsEnabled|Qt.ItemFlag.ItemIsSelectable)
                if not value['enabled']:
                    item.setForeground(0, QBrush(Qt.GlobalColor.darkGray))
                    item.setForeground(1, QBrush(Qt.GlobalColor.darkGray))
                    item.setForeground(2, QBrush(Qt.GlobalColor.darkGray))
                else:
                    item.setForeground(0, QBrush(QColor("#1f5e82")))
                    item.setForeground(1, QBrush(QColor("#1f5e82")))
                    item.setForeground(2, QBrush(QColor("#1f5e82")))
                items.append(item)
            self.tree_1.insertTopLevelItems(0, items)
            self.tree_1.setColumnWidth(0, 160)
            self.tree_1.setColumnWidth(1, 140)
        self.tree_1.itemDoubleClicked.connect(self.selected_admin)
        
        vbox = QVBoxLayout()
        vbox.addWidget(button_box)
        vbox.addWidget(self.tree_1)
        self.box_admins.setLayout(vbox)

    def selected_admin(self, item, col):
        dc.AdminSettings(self.box_admins, self.path, item.text(0))()

    def selected_buttons(self, e):
        if e.objectName() == "admin_edit":
            try:
                admin_name = self.tree_1.selectedItems()[0].text(0)
                dc.AdminSettings(self.box_admins, self.path, admin_name)()
            except IndexError:
                cs.message_inform(self, "Ошибка!", "Не выбран администратор для редактирования.")
        elif e.objectName() == "profile_edit":
            try:
                profile_name = self.tree_2.selectedItems()[0].text(0)
                dc.AdminProfile(self.box_profiles, self.path, profile_name)()
            except IndexError:
                cs.message_inform(self, "Ошибка!", "Не выбран профиль для редактирования.")
        elif e.objectName() == "admin_act":
            dc.SettingsAdminsAuth(self.box_admins, self.path)()

    def _create_box_profiles(self):
        """
        Создаём GroupBox для области "Профили администраторов"
        config_file: admin_profiles_list.json.json
        """
        self.box_profiles = QGroupBox("Профили администраторов")

        button_box = QDialogButtonBox(parent=self.box_profiles)
        button_edit = button_box.addButton("Редактировать", QDialogButtonBox.ButtonRole.ActionRole)
        button_edit.setObjectName("profile_edit")
        button_box.clicked.connect(self.selected_buttons)

        self.tree_2 = cs.MyTree(["Название", "Описание"], style=cs.Style.ListTree)
        try:
            with open(f"{self.path}/admin_profiles_list.json", "r") as fh:
                data = json.load(fh)
        except Exception as err:
            cs.message_alert(self, err, f"Проблема с файлом:\n {self.path}/admin_profiles_list.json")
        else:
            items = []
            for value in data:
                item = QTreeWidgetItem([value['name'], value['description']])
                item.setFlags(Qt.ItemFlag.ItemIsEnabled|Qt.ItemFlag.ItemIsSelectable)
                item.setForeground(0, QBrush(QColor("#1f5e82")))
                item.setForeground(1, QBrush(QColor("#1f5e82")))
                items.append(item)
            self.tree_2.insertTopLevelItems(0, items)
            self.tree_2.setColumnWidth(0, 280)
        self.tree_2.itemDoubleClicked.connect(self.selected_item)

        vbox = QVBoxLayout()
        vbox.addWidget(button_box)
        vbox.addWidget(self.tree_2)
        self.box_profiles.setLayout(vbox)

    def selected_item(self, item, col):
        dc.AdminProfile(self.box_profiles, self.path, item.text(0))()

    def _create_box_sessions_admins(self):
        """
        Создаём GroupBox для области "Сессии администраторов"
        config_file: admin_profiles_list.json.json
        """
        self.box_sessions_admins = QGroupBox("Сессии администраторов")
#        tree = QTreeWidget()
#        tree.setHeaderLabels(["Логин", "Источник", "Начало", "IP-адрес"])
#        tree.setAlternatingRowColors(True)
#        tree.setSortingEnabled(True)
#        tree.setStyleSheet(cs.Style.MainTree)
        tree = cs.MyTree(["Логин", "Источник", "Начало", "IP-адрес"])
#        try:
#            with open(f"{self.path}/admin_profiles_list.json", "r") as fh:
#                data = json.load(fh)
#        except FileNotFoundError:
#            cs.message_alert(self, err, f"Проблема с файлом:\n {self.path}/admin_profiles_list.json")
#        else:
#            items = []
#            for value in data:
#                item = QTreeWidgetItem([value['name'], value['description']])
#                item.setFlags(Qt.ItemFlag.ItemIsEnabled|Qt.ItemFlag.ItemIsSelectable)
#                items.append(item)
#            tree.insertTopLevelItems(0, items)
        tree.setColumnWidth(0, 200)
        tree.setColumnWidth(1, 200)
        tree.setColumnWidth(2, 280)

        vbox = QVBoxLayout()
        vbox.addWidget(tree)
        self.box_sessions_admins.setLayout(vbox)


class Certificates(QWidget):
    """
    Экран "UserGate" --> "Сертификаты".
    """
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.setObjectName("section_mainwidget")
        self.setContentsMargins(0, 0, 0, 0)

        self.button_box = QDialogButtonBox()
        button_edit = self.button_box.addButton("Редактировать", QDialogButtonBox.ButtonRole.ActionRole)
        button_edit.setObjectName("cert_edit")
        button_view = self.button_box.addButton("Показать", QDialogButtonBox.ButtonRole.ActionRole)
        button_view.setObjectName("cert_view")
        self.button_box.clicked.connect(self.selected_buttons)

        self.tree = cs.MyTree(["Название", "Используется", "Издатель", "Субъект", "Действует с", "Истекает"], style=cs.Style.ListTreeEnabledItems)
        try:
            with open(f"{self.path}/certificates_list.json", "r") as fh:
                data = json.load(fh)
        except Exception as err:
            cs.message_alert(self, err, f"Проблема с файлом:\n {self.path}/certificates_list.json")
        else:
            items = []
            for value in data:
                start = cs.convert_date(value['not_before'])
                end = cs.convert_date(value['not_after'])
                item = QTreeWidgetItem([value['name'], cs.appointment.get(value['role'], value['role']), value['issuer']['common_name'], value['subject']['common_name'], start, end])
                item.setFlags(Qt.ItemFlag.ItemIsEnabled|Qt.ItemFlag.ItemIsSelectable)
                items.append(item)
            self.tree.insertTopLevelItems(0, items)
            self.tree.setColumnWidth(0, 180)
            self.tree.setColumnWidth(1, 160)
            self.tree.setColumnWidth(2, 200)
            self.tree.setColumnWidth(3, 200)
            self.tree.setColumnWidth(4, 140)
        self.tree.itemDoubleClicked.connect(self.selected_item)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(self.button_box)
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

    def selected_buttons(self, event):
        try:
            sert_name = self.tree.selectedItems()[0].text(0)
        except IndexError:
            cs.message_inform(self, "Ошибка!", "Не выбран сертификат.")
        else:
            if event.objectName() == "cert_edit":
                dc.CertSettings(self.tree, self.path, sert_name)()
            elif event.objectName() == "cert_view":
                dc.CertView(self.tree, self.path, sert_name)()

    def selected_item(self, item, col):
        dc.CertSettings(self.tree, self.path, item.text(0))()


class Zones(QWidget):
    """
    Экран "Сеть" --> "Зоны".
    """
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.setObjectName("section_mainwidget")
        self.setContentsMargins(0, 0, 0, 0)

        self.button_box = QDialogButtonBox()
        button_edit = self.button_box.addButton("Редактировать", QDialogButtonBox.ButtonRole.ActionRole)
        button_edit.setObjectName("zone_edit")
        self.button_box.clicked.connect(self.selected_buttons)

        self.tree = cs.MyTree(["Имя зоны", "Защита от DoS включена для", "Защита от спуфинга", "Контроль доступа"], style=cs.Style.ListTreeEnabledItems)
        try:
            with open(f"{self.path}/config_zones.json", "r") as fh:
                data = json.load(fh)
        except Exception as err:
            cs.message_alert(self, err, f"Проблема с файлом:\n {self.path}/config_zones.json")
        else:
            items = []
            for value in data:
                dos = self.get_protect_dos(value['dos_profiles'])
                antispoof = self.get_protect_spoof(value)
                services_access = self.get_services_access(value['services_access'])
                item = QTreeWidgetItem([value['name'], dos, antispoof, services_access])
                item.setFlags(Qt.ItemFlag.ItemIsEnabled|Qt.ItemFlag.ItemIsSelectable)
                items.append(item)
            self.tree.insertTopLevelItems(0, items)
            self.tree.setColumnWidth(0, 180)
            self.tree.setColumnWidth(1, 200)
            self.tree.setColumnWidth(2, 200)
        self.tree.itemDoubleClicked.connect(self.selected_item)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(self.button_box)
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

    def get_protect_dos(self, dos_profiles):
        result = ", ".join([x['kind'].upper() for x in dos_profiles if x['enabled']])
        return result if result else "Ничего"

    def get_protect_spoof(self, spoof_data):
        if not spoof_data['enable_antispoof']:
            return "Отключено"
        else:
            result = "Включено, адреса:\n"
            if not spoof_data['networks']:
                result += "Локальные адреса зоны"
            else:
                if spoof_data['antispoof_invert']:
                    for x in spoof_data['networks']:
                       result += "\u0336" + '\u0336'.join(x) + "\u0336\n"
                else:
                    result += "\n".join(spoof_data['networks'])
            return result.rstrip()

    def get_services_access(self, services_access):
        result = ", ".join([cs.zone_services[x['service_id']] for x in services_access if x['enabled']])
        return result if result else "Всё отключено"

    def selected_buttons(self, event):
        try:
            zone_name = self.tree.selectedItems()[0].text(0)
        except IndexError:
            cs.message_inform(self, "Ошибка!", "Не выбрана зона для просмотра.")
        else:
            if event.objectName() == "zone_edit":
                dc.ZoneSettings(self.tree, self.path, zone_name)()

    def selected_item(self, item, col):
        dc.ZoneSettings(self.tree, self.path, item.text(0))()


class Interfaces(QWidget):
    """
    Экран "Сеть" --> "Интерфейсы".
    """
    def __init__(self, path):
        super().__init__()
        self.path = path
        self.setObjectName("section_mainwidget")
        self.setContentsMargins(0, 0, 0, 0)

        self.button_box = QDialogButtonBox()
        button_edit = self.button_box.addButton("Редактировать", QDialogButtonBox.ButtonRole.ActionRole)
        button_edit.setObjectName("iface_edit")
        self.button_box.clicked.connect(self.selected_buttons)

        self.tree = cs.MyTree(["Тип", "Название", "Режим", "IP интерфейса", "MAC-адрес", "Зона", "MTU", "DHCP-релей", "Интерфейсы",
                               "Тип интерфейса", "Виртуальный маршрутизатор", "Профиль netflow"], style=cs.Style.ListTree)
        try:
            with open(f"{self.path}/config_interfaces.json", "r") as fh:
                data = json.load(fh)
        except Exception as err:
            cs.message_alert(self, err, f"Проблема с файлом:\n {self.path}/config_interfaces.json")
        else:
            items = []
            cluster = QTreeWidgetItem(["Узел кластера: cluster"])
            for value in data:
                if value['kind'] == "vpn":
                    mode = "Статический" if value['mode'] == "static" else "Динамический"
                    ip = "\n".join(value['ipv4'])
                    zone = value['zone_id'] if value['zone_id'] else "---"
                    netflow_profile = "---" if value['netflow_profile'] == "undefined" else value['netflow_profile']
                    item = QTreeWidgetItem(["VPN", value['name'], mode, ip, "", zone, str(value['mtu']), "", "", "Layer 3", "", netflow_profile])
                    item.setFlags(Qt.ItemFlag.ItemIsEnabled|Qt.ItemFlag.ItemIsSelectable)
                    items.append(item)

#                    dhcp_relay = "\n".join(value['dhcp_relay']['servers'])

            self.tree.insertTopLevelItems(0, items)
            self.tree.setColumnWidth(0, 180)
            self.tree.setColumnWidth(1, 160)
            self.tree.setColumnWidth(2, 200)
            self.tree.setColumnWidth(3, 200)
            self.tree.setColumnWidth(4, 140)
        self.tree.itemDoubleClicked.connect(self.selected_item)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(self.button_box)
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

    def selected_buttons(self, event):
        try:
            sert_name = self.tree.selectedItems()[0].text(0)
        except IndexError:
            cs.message_inform(self, "Ошибка!", "Не выбран сертификат.")
        else:
            if event.objectName() == "cert_edit":
                dc.CertSettings(self.tree, self.path, sert_name)()
            elif event.objectName() == "cert_view":
                dc.CertView(self.tree, self.path, sert_name)()

    def selected_item(self, item, col):
        dc.CertSettings(self.tree, self.path, item.text(0))()
