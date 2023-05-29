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
import threading, time
import PySimpleGUI as sg
import user_settings as us
import snmp_query as sq


THREAD_EVENT = '-THREAD-'
SETTINGS_PATH = '.'
FIRST_INIT = 1
SETTINGS_UPDATED = 2
window = ''
window_status = FIRST_INIT
ports = {}
sg.user_settings_filename(path=SETTINGS_PATH)

def get_location():
    """
    Определение координат окна.
    """
    arr = sg.user_settings_get_entry('Location')
    if arr and arr[0] and arr[1]:
        return (arr[0]-5, arr[1]-51)
    else:
        return (150, 130)

def set_location(window):
    """
    Отслеживаем положение окна на экране и запомнаем, если изменилось.
    """
    current_location = window.CurrentLocation()
    if current_location != sg.user_settings_get_entry('Location'):
        sg.user_settings_set_entry('Location', window.CurrentLocation())

def make_window():
    sg.theme('Dark')
    sg.SetOptions(
                  progress_meter_color = ('white', '#404040')
                 )
    menu_def = [
        ['Main', ['Параметры', '!Интерфейсы', '!Графики', '---', 'Exit']],
    ]
    left_col1 = [
        [sg.Text('Имя:', font=(22), pad=(0, (0, 8))), sg.Text(size=(14, 1), pad=(0, (0, 8)), key='-NAME-', text_color='lightgreen', font=(22))],
        [sg.Text('Загрузка процессора (%):', pad=(0, 2), size=(23, 1)), sg.Text(size=(3, 1), justification='right', pad=(0, 2), key='-CpuLoad-')],
        [sg.Text('Занятая память (%):', pad=(0, 2), size=(23, 1)), sg.Text(size=(3, 1), justification='right', pad=(0, 2), key='-MemoryUsed-')],
        [sg.Text('Журналами занято (%):', pad=(0, 2), size=(23, 1)), sg.Text(size=(3, 1), justification='right', pad=(0, 2), key='-LogSpace-')],
        [sg.Text('Используемые vCPU:', pad=(0, 2), size=(23, 1)), sg.Text(size=(3, 1), justification='right', pad=(0, 2), key='-VcpuUsage-')],
        [sg.Text('Количество vCPU:', pad=(0, 2), size=(19, 1)), sg.Text(size=(7, 1), justification='right', pad=(0, 2), key='-VcpuCount-')],
    ]
    left_col2 = [
        [sg.Text('IP:', font=(22), pad=(0, (0, 7))), sg.Text(size=(14, 1), pad=(0, (0, 7)), key='-IP-', text_color='lightgreen', font=(22))],
        [sg.Text('Блок питания-1: ', pad=(0, 2), size=(14, 1)), sg.Text(size=(16, 1), justification='right', pad=(0, 2), key='-PowerStatus1-')],
        [sg.Text('Блок питания-2: ', pad=(0, 2), size=(14, 1)), sg.Text(size=(16, 1), justification='right', pad=(0, 2), key='-PowerStatus2-')],
        [sg.Text('Raid Status: ', pad=(0, 2), size=(14, 1)), sg.Text(size=(16, 1), justification='right', pad=(0, 2), key='-RaidStatus-')],
        [sg.Text('Активные пользователи: ', pad=(0, 2), size=(21, 1)), sg.Text(size=(9, 1), justification='right', pad=(0, 2), key='-UsersCounter-')],
        [sg.Text(pad=(0, 2))],
    ]
    image_col = [[sg.Image(key='-MAIN_IMAGE-', pad=((2, 0), (0, 2)))]]
    left_col_summ = [
        [sg.Column(left_col1, pad=(0, 0)), sg.Column(left_col2, pad=((10, 0), 0))],
        [sg.HSep()],
    ]
    layout = [
        [sg.Menu(menu_def, key='-Menu-')],
        [sg.Column(left_col_summ, pad=(0, 0)), sg.Column(image_col, pad=(0, 0))],
        
    ]
    return sg.Window(
        'Состояние UTM',
        layout, button_color=('Green', 'White'),
        icon="favicon.png",
        location=get_location(),
        enable_close_attempted_event=True,
        finalize=True
    )

def init_window(window):
    """
    Начальная инициализация окна.
    """
    ports = {}
    window.bind('<Button-3>', '+RIGHT CLICK+')
    status = SETTINGS_UPDATED
    ip = sg.user_settings_get_entry('IP')
    community = sg.user_settings_get_entry('Community')
    if not ip or not community:
        return FIRST_INIT, '', '', {}
    else:
        utm_name = sg.user_settings_get_entry('Name')
        window['-NAME-'](utm_name)
        window['-IP-'](ip)
        status = check_host(ip, community)
        if status != FIRST_INIT:
            status, ports = check_ports(ip, community)
            update_menu(window)
            update_window(window, ports)
        return status, ip, community, ports

def update_window(window, ports):
    graphs_list = [sg.Image(filename=f'data/{port.name}.png', pad=(0, 0), key=f'{port.name}') for port in ports.values()]
    if len(graphs_list)%2 != 0:
        graphs_list.append(sg.Text("", visible=False))
    layout = [[graphs_list[i], graphs_list[i+1]] for i in range(0, len(graphs_list)-1, 2)]
    window.extend_layout(window, layout)

def update_menu(window):
    menu_def = [
        ['Main', ['Параметры', 'Интерфейсы', 'Графики', '---', 'Exit']],
    ]
    window['-Menu-'].update(menu_def)

def check_host(ip, community):
    status = SETTINGS_UPDATED
    if sq.check_snmp(ip, community) == 'timeout':
        sg.PopupError('Ошибка!', 'Данный узел не отвечает на SNMP запросы.', keep_on_top=True,)
        status = FIRST_INIT
    else:
        sq.create_host_rrd()
    return status

def check_ports(ip, community):
    status = SETTINGS_UPDATED
    used_ports = sg.user_settings_get_entry('Ports')
    trafic_time = sg.user_settings_get_entry('TraficTime')
    err, ports = sq.get_ports(ip, community, used_ports, trafic_time)
    if err == 3:
        sg.PopupError(f'Ошибка!', 'На UTM в настройках SNMP не указано событие:\n"Таблица статистики сетевых интерфейсов"', keep_on_top=True)
        status = FIRST_INIT
    if err != 0:
        sg.PopupError(f'Ошибка ({err})!', 'Устройство не ответило на SNMP запрос.', keep_on_top=True)
        status = FIRST_INIT
    return status, ports

def thread_for_snmp():
    global window
    global window_status
    global ports
    while True:
        if window_status == 2:
            perf_time = sg.user_settings_get_entry('PerformanceTime')
            trafic_time = sg.user_settings_get_entry('TraficTime')
            ip = sg.user_settings_get_entry('IP')
            community = sg.user_settings_get_entry('Community')
            err, data = sq.get_utm_status(ip, community)
            if not err:
                window['-CpuLoad-'](data.get('CpuLoad', '--'))
                window['-MemoryUsed-'](data.get('MemoryUsed', '--'))
                window['-LogSpace-'](data.get('LogSpace', '--'))
                window['-VcpuUsage-'](data.get('vcpuUsage', '--'))
                window['-VcpuCount-'](data['vcpuCount']*100 if data.get('vcpuCount', False) else '--')
                window['-PowerStatus1-'](data.get('PowerStatus1', '--'))
                window['-PowerStatus2-'](data.get('PowerStatus2', '--'))
                window['-RaidStatus-'](data.get('RaidStatus', '--'))
                window['-UsersCounter-'](data.get('usersCounter', '--'))
                if data:
                    data['vcpuUsage'] = data['vcpuUsage']*100 / (data['vcpuCount']*100)
                sq.update_host_rrd(data.get('CpuLoad', 'U'), data.get('vcpuUsage', 'U'), data.get('MemoryUsed', 'U'))
                sq.create_host_graph(perf_time)
                window['-MAIN_IMAGE-']('data/main.png')
            else:
                window_status = 1
                window.write_event_value('-THREAD-', (err, data))

            if ports:
                state = sq.get_port_counter(ip, community, ports)
                for port in ports.values():
                    port.create_rrd_graph(trafic_time)
                    window[port.name](f'data/{port.name}.png')

        time.sleep(1)

def main():
    global window
    global window_status
    global ports
    window = make_window()
    window_status, ip, community, ports = init_window(window)
    threading.Thread(target=thread_for_snmp, args=(), daemon=True).start()
    while True:
        event, values = window.read()
        set_location(window)
        if (event == sg.WINDOW_CLOSE_ATTEMPTED_EVENT or event == 'Exit') and sg.popup_yes_no('Вы действительно желаете закрыть окно?') == 'Yes':
            break
        elif event == 'Параметры':
            old_status = window_status
            window_status = FIRST_INIT
            if us.make_settings() == SETTINGS_UPDATED:
                utm_name = sg.user_settings_get_entry('Name')
                ip = sg.user_settings_get_entry('IP')
                community = sg.user_settings_get_entry('Community')
                window['-NAME-'](utm_name)
                window['-IP-'](ip)
                update_menu(window)
                window_status = check_host(ip, community)
            else:
                window_status = old_status

        elif event == 'Интерфейсы':
            all_ports = sq.get_all_ports(ip, community)
            if not all_ports:
                sg.PopupError(f'Ошибка!', 'На UTM в настройках SNMP не указано событие:\n"Таблица статистики сетевых интерфейсов"', keep_on_top=True)
            else:
                old_status = window_status
                window_status = FIRST_INIT
                if us.make_ports(all_ports) == SETTINGS_UPDATED:
                    window.close()
                    del window
                    window = make_window()
                    window_status, ip, community, ports = init_window(window)
                else:
                    window_status = old_status

        elif event == 'Графики':
            old_status = window_status
            window_status = FIRST_INIT
            if us.make_graphs() == SETTINGS_UPDATED:
                sq.remove_host_graph()
                for port in ports.values():
                    port.remove_rrd_graph()
                window_status = SETTINGS_UPDATED
            else:
                window_status = old_status

        elif event == THREAD_EVENT:
            if values[THREAD_EVENT][0] == 3:
                sg.PopupError(f'Ошибка!', f'В snmp_query.get_utm_status не указаны необходимые события {values[THREAD_EVENT][1]}.', keep_on_top=True)
            else:
                sg.PopupError(f'Ошибка: {values[THREAD_EVENT][0]}!', f'Устройство не ответило на SNMP запрос.\n{values[THREAD_EVENT][1]}', keep_on_top=True)

    window.close()

if __name__ == '__main__':
    main()
