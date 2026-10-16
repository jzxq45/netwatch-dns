# ANDROID: troubleshooting

## «Не могу подключиться»
- monitor.exe запущен на ПК? Окно закрыто = сервера нет. Порт виден в
  строке `msg=started ... web=127.0.0.1:8080` — в «Настройках» приложения
  адрес должен указывать на IP ПК (например http://192.168.0.150:8080).
- Телефон и ПК в одной Wi-Fi сети; ПК не в публичном профиле Windows:

  `netsh advfirewall firewall add rule name="monitor 8080" dir=in action=allow protocol=tcp localport=8080`

## Белый экран
- Старая версия панели в кэше WebView: «Настройки» → «Сохранить» — приложение
  перезагрузится; либо смахни SwipeRefresh, либо очисти приложение.
- 401 Unauthorized в logcat: в monitor.yaml включён web_token, а в
  приложении токен не задан → впиши тот же токен в «Настройках».

## «cleartext not permitted»
Android запрещает открытый HTTP. Проект включает
`usesCleartextTraffic=true` и `network_security_config.xml`
(base-config cleartextTrafficPermitted) — если собирал со своей конфигой,
проверь что оба пункта на месте. Android XML не поддерживает подсети
(192.168.0.0/24) — поэтому глобальное разрешение; наружу приложение не
смотрит (адрес только ваш сервер).

## HTTP 401
Токен не совпадает с web_token сервера. Пути передачи: `?token=…` в URL
(ставится cookie на 30 дней), заголовок X-Auth-Token, localStorage.
«Проверить соединение» в «Настройках» отправляет X-Auth-Token и показывает
точный HTTP-код.

## Потерял ничего
Все данные только с вашего сервера; приложение не имеет реклам/аналитики.