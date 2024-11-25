<h2 align="center">Получение списка активных IP-адресов на UTM UserGate.</h2>
<h3 align="center">(Версия 1.3)</h3>
<p align="center"><img src="utm.png"></p>

Программа предназначена для оперативного получения списка активных IP-адресов, занимающих лицензию
на NGFW UserGate. Можно сохраняеть список IP-адресов в файл вида <i>"active_ips (date_time).txt"</i> в каталог
<b>data</b> в текущей директории.<br>
Так же программа выводит сведения о текущей лицензии UTM.

Программа работает в Ubunty версии 24.04 или выше.<br>
Скачать архив <b>ug_view_license.zip</b>, распаковать.
Файл <b>ug_view_license</b> сделать исполняемым, запустить <b>ug_view_license</b> в терминале или сделать ярлык на рабочий стол.

Программа Запрашивает ip узла, login и пароль администратора UTM.

Программа работает на UG NGFW версии 6 и выше. Для работы программы на интерфейсе, к которому производится
подключение, необходимо включить сервис xml-rpc. Если используется зона Management, то этого делать не надо,
так как сервис xml-rpc на интерфейсе Management включён по умолчанию.

Включение сервиса xml-rpc на зоне:
1. Открыть веб-консоль администратора таким образом: https://<usergate_ip>:8001/?features=zone-xml-rpc
2. В настройках нужной зоны активировать сервис "XML-RPC для управления".

<b>Примечание:</b>
Если версия вашего UG NGFW меньше , обратитесь в техподдержку UserGate для включения
необходимых API.