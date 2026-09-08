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
