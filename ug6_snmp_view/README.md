<h2 align="center">Опрос UTM UserGate по SNMP.</h2>
<h3 align="center">(Версия 3.1)</h3>

Программа предназначена для оперативного получения текущего состояния Межсетевого экрана UserGate версии 6.

<p align="center"><img src="utm.png"></p>

Программа работает в Ubuntu версии 22.10 или выше.<br>

Опрос производиться по SNMP c UserGate NGFW версии 6. Выводяться следующие параметры:
- загрузка процессора;
- занятая оперативноя память;
- объём дискового пространства, занятое журналами;
- использование vCPU;
- число задействованных vCPU;
- состояние блоков питания;
- состояние массива Raid;
- число активных пользователей;
- трафик на сетевых интерфейсах.

Установка:
1. Скачать архив ug6_snmp_view.zip, распаковать.
2. Файл ug6_snmp_view сделать исполняемым.
3. Запустить ug6_snmp_view.

После первоначального запуска необходимо в меню "Main" --> "Параметры" открыть окно ввода настроек подключения к NGFW. Необходимо ввести:
- имя устройства,
- IP адрес,
- community.

После этого в меню "Main" --> "Интерфейсы" задать интерфейсы для опроса.<br>
В "Main" --> "Графики" можно выбрать диапазон графиков: 20 минут, 1 час или 1 день.

Настройки сохраняются в файле ug_snmp_view.json. Данный файл создаётся в директории программы.

На UTM в разделе "Диагностика и мониторинг" --> "SNMP" в правиле snmp надо поставить версию: "SNMP v2".
На вкладке "События" включить:
- Таблица статистики сетевых интерфейсов;
- Загрузка vCPU;
- Количество vCPU;
- Изменён статус RAID;
- Изменён статус блока питания;
- Высокая загрузка процессора;
- Высокая загрузка памяти;
- Недостаточно места в разделе для журналов;
- Количество лицензий использовано.

Изменения:<br>
29.05.2023 Исправлено отображение использование vcpu на графике.
24.05.2023 Устранены задержки в работе графического интерфейса.