# Terminology guide

Проект документируется нейтральными техническими терминами. Это не игра
слов — это точные названия функций, которые дойдут до других людей:
членов семьи, сотрудников, читающих README.

| Wrong (не использовать) | Correct | Почему |
| --- | --- | --- |
| «шпионим за трафиком», «spy on devices» | network telemetry; DNS resolution monitoring | Активность сети собирается в области DNS; телеметрия — точный нейтральный срок |
| «обход DNS», «DNS фильтр bypass» | DNS policy enforcement | Локальная политика себя enforced; клиенты — не «враг» |
| «перехватываем запросы», «перехват» | DNS resolution monitoring | Запросы приходят к нам от routers, не «перехват» |
| «глушим DoH / глушим endpoint» | enforce clients to use the configured resolver | Правильная формулировка функции |
| «подменяем ответ» | returning NXDOMAIN per local policy | Как RFC 2308 описывает negative response |
| «слежка», «spy», «hack» | — | Никогда: см. README «What it does NOT do» |

## Единственный корректный контекст слова bypass

`preventing DNS filtering bypass by clients` — один раз существует
место, где слово bypass допустимо: описывать, как клиенты, которые
делают попытки пропустить свой собственный resolver (hardcoded DoH).
Ничего о действиях администратора — только про устройство клиента.

## Ссылки для чтения

- [LEGAL.md](LEGAL.md) — правовой и этический скоуп
- README.md → «What it does NOT do» — обязательный набор отрицаний скоупа.