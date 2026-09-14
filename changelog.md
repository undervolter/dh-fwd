[15.09.26] dh-fwd v2.3
```md
 - [+] Нативный P2P-портсканер (--scan) без локального форвардинга | Native P2P port scanner (--scan) without opening local listeners
 - [+] Защита от рейтлимита: последовательное сканирование с 4-секундной паузой и живым таймером | Rate-limit resilience: sequential scanning with 4s cooldown pacing and live countdown
 - [~] Упрощённый ввод учётных данных (--creds, -c login:password) | Simplified credential input (--creds, -c login:password)
 - [~] Автоматическое извлечение RandSalt из зашифрованного Info-блоба камеры | Automatic RandSalt resolution from device encrypted Info blob
```

[14.09.26] dh-fwd v2.2.0
```md
 - [+] Fallback для TCP Relay (-R) (проверка совместимости)  | TCP relay fallback (-R) (compatibility check)
 - [+] Авто-дроп неактивных портов камеры | Auto-drop inactive ports
 - [+] Переработан механизм реконнекта без нового построения туннеля | Recoded reconnect mechanism without building a new tunnel
 - [+] Глобальный семафор на /relay/agent (защита easy4ip/dolynk от потери пакетов) | Global semaphore on concurrent /relay/agent allocations
 - [+] Ротация и failover relay-диспетчеров | Relay dispatcher rotation and failover
 - [+] Ретрансмиты /relay/start с коротким чтением | Bounded /relay/start retransmits
 - [~] fixed: поддержка русской раскладки клавиатуры (с/к/р/д/в) в диалогах выбора, устранено зацикливание промпта | fixed: Russian keyboard layout support in fail prompts, preventing infinite input loops
 - [~] fixed: ложные дисконнекты в TCP-relay — интервал keepalive снижен с 20с до 7с (таймаут канала был 10с) | fixed: false TCP-relay disconnects — lowered keepalive interval from 20s to 7s (below 10s heartbeat timeout)
 - [~] fixed: nil-паника в clientReader при отправке DISC в обнулённый primary после reset | fixed: nil pointer dereference in clientReader sending DISC to a reset primary
 - [~] fixed: игнорирование мусорных и не-PTCP пакетов в readLoop вместо аварийного закрытия живого туннеля | fixed: ignore non-PTCP frames and late ACK duplicates instead of tearing down healthy tunnels
 - [~] fixed: мгновенный выход при занятом локальном порту ("no listeners available") без бесполезных 4-х циклов ретрая | fixed: fast abort on terminal listener bind errors instead of burning retry attempts
 - [~] fixed: инициализация lastRecv текущим временем в NewUDP (предотвращает ложный мгновенный таймаут сокета) | fixed: initialize UDP.lastRecv to time.Now() avoiding false instant timeouts
 - [~] fixed: утечка сокетов в очереди acceptCh при закрытии туннеля | fixed: socket leak in acceptCh during tunnel teardown
```
misc:

```md
 - [+] Механизм автообновления | Auto upgrade mechanism
 - [+] Немного изменённый UI | A little bit changed UI
 - [~] reworked: Механизм логов - теперь они пишутся не в терминал а в .log |  Log mechanism - now they're writing in .log, not in stdout
```

[11.09.26] dh-fwd v2.1.1
 - [~] Добавлен механизм повторного соединения в случае если промежуточный сервер не отвечает | Added reconnect mechanism in case the relay server does not respond

[08.09.26] dh-fwd v2.1.0
 - [+] Добавлен профиль dmss для лучшей совместимости с камерами выпущенными после июля 2024 | Added dmss profile for better compatibility with cameras released after July 2024
 
[04.09.26] dh-fwd v2.0.1
 - [+] Добавлен прогресс бар для интуитивности | Added progress bar for better UX
 - [~] Изменён механизм реконнекта при зависании на запрашивании relay | Improved reconnect mechanism when hanging on relay allocation requests

[02.09.26] dh-fwd v2.0.0

 - [+] Сделан рекод сетевой части | Recoded network layer
 - [~] fixed: баг который не давал войти в панель камеры через браузер | fixed: bug preventing login to the camera web panel via browser
 - [+] Увеличена скорость работы | Improved overall performance
 - [-] Удалён режим decode за ненадобностью | Removed decode mode as deprecated
 - [+] Добавлен режим SmartPSS (форвардинг портов 80 и 37777 одновременно) | Added SmartPSS mode (simultaneous forwarding of ports 80 and 37777)
 - [+] Добавлен флаг --pools (количество пулов, по дефолту - 50) | Added --pools flag (pool size, default is 50)
 - [+] Добавлена поддержка камер с Type 1 Auth | Added support for cameras requiring Type 1 Auth

[28.08.26] dh-fwd v1.0.1

 - [~] Изменён форвардинг портов с 0.0.0.0 на localhost | Changed port forwarding bind from 0.0.0.0 to localhost

[12.08.26] dh-fwd v1

 - [+] Вышел в релиз | Initial release
