# dh-fwd — полный построчный анализ кодовой базы

Эталонный документ для реверса P2PDll.dll: полное описание текущего поведения dh-fwd
(все 15 файлов, ~7360 строк, без тестов), все wire-форматы, константы, таймеры —
и их происхождение (подтверждено адресом DLL / выведено из captures / изобретение dh-fwd).

Дата анализа: 2026-10-24, коммит `1c38949` (v2.5 / 0.1).

---

## 1. Архитектура одним взглядом

```
main.go ──► core.Execute() (cli.go)
              │
              ├─ флаги, парсинг портов, профили (smartpss/dmss, profile.go)
              ├─ checkUpdate() (updater.go, GitHub API)
              ├─ runSingle / runSingleRace / runMulti
              │     └─ Tunnel (tunnel.go)
              │           ├─ establish(): 4 фазы облачного хендшейка
              │           │    1. /online/p2psrv/<SN> → US (device p2p server)
              │           │    2. /info/device/<SN> → Info blob (порты, randsalt)
              │           │    3. /device/<SN>/p2p-channel + relay agent alloc
              │           │    4. STUN punch ⇄ relay channel — гонка
              │           ├─ serve(): listeners → BIND realm → DATA
              │           └─ readLoop ×2 / heartbeat / zombie / poolKeeper
              ├─ UDP-транспорт (helpers.go): DH HTTP-over-UDP + PTCP + ARQ
              ├─ TOU-over-TCP (tou.go + tcp_relay.go): запасной путь
              ├─ relay resilience (relay_resilience.go): backoff, zombie
              └─ http_accel.go (ДИСЁЙБЛЕН), mtu.go, ui.go, logger.go
```

Три data-пути, приоритет:
1. **Direct P2P** — STUN punch через PubAddr/LocalAddr устройства, PTCP over UDP
2. **UDP relay** — через relay agent (mainRemote), PTCP over UDP
3. **TCP relay** — TOU-фрейминг over TCP (флаг `-R` или fallback по Policy `tcprelay`)

---

## 2. main.go (14 строк)

`Version = "0.1"` (ZeroVer) → присваивается `core.Version` → `core.Execute()`.
Больше ничего. ldflags могут переопределить.

---

## 3. core/cli.go (1080 строк)

### 3.1 Состояния портов

`PortState`: `PortConnecting` → `PortOK` / `PortFAIL` / `PortDROPPED`.
`PortRegistry` — мьютекс, массивы specs/states/reasons/actualPorts, счётчик `pending`,
небуферизованный-до-единицы `notify`-канал. `set()` при переходе из Connecting
декрементит pending; когда pending==0 и есть FAIL — сигнал в notify (главный цикл
runMulti просыпается и решает: промпт / drop / retry).
`drop()` помечает DROPPED (авто-дроп фейлов при ≥1 OK).

### 3.2 parseArgs (172–190)

Разбор перемешанных флагов и позиционных аргументов: стандартный FlagSet не
переваривает `dh-fwd SN -p 80`, поэтому цикл: Parse → первый позиционный
забираем → остаток парсим снова. `--` завершает.

### 3.3 Execute() — все флаги (204–247)

| Флаг | Значение | Заметки |
|---|---|---|
| `--debug, -d` | false | протокол-дамп в лог |
| `--info` | — | расшифровать Info blob, exit |
| `--test` | — | резолв портов камеры, печать плана, exit |
| `--test-mtu` | — | PMTUD-диагностика, exit |
| `--R, --tcp-relay` | false | принудительный TCP-relay путь |
| `--2, --smartpss, --smart-pss` | — | пресет: 80+37777 на ephemeral |
| `--mtu` | 0 (auto) | максимум 1280 |
| `--pool, --pools` | 50 | pre-bound realms на порт; 0 = выкл |
| `--creds, -c` | "" | user:pass → type=1 |
| `--t, --type` | 0 | 0 без auth, 1 с auth |
| `--u/-username`, `--P/-password` | "" | |
| `--s, --randsalt` | "" | из info blob или флага |
| `--port, -p` | "554:554" | грамматика ниже |
| `--threads, -mt` | 3 | параллельные туннели |
| `--log-retries, -lr` | false | |
| `--heartbeat-timeout, -hb` | 30s | PTCP heartbeat timeout |
| `--app-relay, -ar` | false | app-relay диалект, без 0x17/0x19 |
| `--relay, -r` | false | форс UDP-relay, без STUN punch |
| `--app` | smartpss | smartpss \| dmss |
| `--y, --yes` | false | без подтверждений |
| `--race` | false | гонка профилей/путей параллельно |
| `--reconnect, -rc` | false | вечный реконнект |

`--creds` распознаётся отдельно → dtype=1. `appExplicit` через `flag.Visit`.
Неявный `--app` → fallback-цепочка `[smartpss, dmss]`.

Грамматика `--port`: `"local:remote"` CSV, без `:` — только remote (local
ephemeral), диапазоны `80-85`, `0:81` — ephemeral. Один remote → бродкаст на
все local. Несовпадение длин (кроме 1) — ошибка. Default `554:554`.

### 3.4 runPortTest (439–539)

Тот же путь, что туннель: warmup → `/online/p2psrv` → US-socket →
`probeDeviceInfo` → `applyDevicePorts` на голом `&Tunnel{}` → печать
httpport/privport/rtspport (default 80/37777/554) + план форвардинга с
пометкой rewritten. Exit 0 если устройство ответило хотя бы пустым blob.

### 3.5 runSingleRace (632–709)

По туннелю на профиль, `handshake()` параллельно, канал результатов.
Первый без ошибки — winner; лузеры `close()`. 404 запоминается для финального
сообщения. Winner → `serve()` → при ошибке `reset()` + `runWithRetries` с
onExhausted = exit(1).

### 3.6 runSingle (711–767)

Последовательно по профилям; `runWithRetries` на каждом. 404 → следующий
профиль (FailInPlace + 400ms пауза + зачистка строки ANSI). Auth-ошибка →
exit(1) сразу.

### 3.7 verifyDevice (777–857) — префлайт multi-режима

Тот же логический канал-обмен, что в хендшейке:
1. warmup + `/online/p2psrv/<SN>`; нет `body/US` → false.
2. Type-1 + autoSalt-профиль + нет randsalt → дозвон до US, `resolveAutoSalt`
   из blob (fail-closed: blob unusable → устройство «недостижимо»).
3. `channelSender` на main-сокете: реальный fwd-порт в ClientId, ранний ack
   через `waitChannelEarlyAck` (окно channelAckWindow), затем fallback на два
   `Read(true, RELAY_READ_TIMEOUT)` (code<200 → ещё один read).
4. 403: dtype=0 → «requires auth», dtype>0 → «auth failed».

Возвращает `(ok, resolvedSalt)` — соль переиспользуются всеми портами.

### 3.8 runMulti (869–1044)

Verify (последовательно или race), затем `distribute`: round-robin specs по
threads, туннель на группу, `go runWithRetries(t, nil, nil)`. Главный цикл
на `reg.notify`: все pending закрыты → fails? все 404 → deviceNotFound+exit;
есть OK → авто-дроп фейлов; иначе промпт `showFailPrompt` (r/d/c, включая
русскую раскладку: к/р, д/в/ш, с). Сводка `Listening on :p1,p2...`,
прямая/relay-ветка печатью, `StartUptimeTracker`.

---

## 4. core/profile.go (163 строки) — диалекты клиентов

Пара-гейтинг подтверждён (DMSS-bound устройство отвечает только DMSS-identity,
replay 2026-09-06, docs/dmss/p2p-cloud-re.md §8).

| Поле | smartpss | dmss |
|---|---|---|
| mainServer | www.easy4ipcloud.com | p2p.dolynkcloud.com |
| mainPort | 8800 | 8800 |
| WSSE user | `cba1b29e32cb17aa46b8ff9e73c7f40b` | `793k5zdi4dd5f037sooag8yo_dolynkc` |
| WSSE key | `996103384cdf19179e19243e959bbf8b` | `ef8hatgmcuk4qamgg4fxx19x33s9q1xy` |
| verbs | DHGET / DHPOST | NFGET / NFPOST |
| Created | UTC + литерал `Z` | локальное время, числовой offset `-07:00` |
| X-ToUType | — | `Client/Dmss_Android` |
| X-Version / X-Sversion | — | `6.7.15` / `1.1.0` |
| warmup | `/probe/p2psrv` **с** auth | `/online/stun` **без** auth |
| header order | legacy: CSeq сразу после request line | app: version-headers → pcs-id → ToUType → CSeq → auth |
| CSeq | глобальный счётчик | случайный **знаковый** int32 (int32 при печати — уходит в минус) |
| x-pcs-request-id | — | да (randomHex(16)) |
| extendedBody (канальный XML) | — | NatValueT/version/sVersion/Pid/ClientId |
| identifyHex | `%x` без паддинга | `%02x` с нулевым паддингом |
| localChannel | — | да (GET /device/<SN>/local-channel после establishment) |
| autoSalt | — | да (randsalt из Info blob) |
| noRelayAuth | — | да (data-канал без 0x17/0x19) |
| relayAgentOptional | — | да (лучше-эффорт, 3s) |
| channelRetransmit | да | да |

`randomHex(n)`: crypto/rand → 2n lowercase hex (формат x-pcs-request-id и
ClientId приложения).

---

## 5. core/helpers.go (988 строк) — крипта, PTCP, UDP-обёртка

### 5.1 Константы облака (30–38)

```
MAIN_SERVER  = www.easy4ipcloud.com   MAIN_PORT = 8800
WSSE_USERNAME/KEY — пара SmartPSS (публичная, вшита в каждый клиент)
AES_IV       = "2z52*lk9o6HRyJrf"    (16 байт, для OFB-шифра LocalAddr)
```

### 5.2 Type-1 device auth (52–121)

1. **Master key**: `MD5(user + ":Login to " + salt + ":" + pass)` → 32 ASCII-символа ВЕРХНЕГО hex (`%X`).
2. **Nonce**: случайный **знаковый** int32 (диапазон −2³¹..2³¹−1, как приложение).
3. **DK**: `PBKDF2-HMAC-SHA256(masterKey, decimal(nonce), 20000 итераций, 32B)`.
4. **LocalAddr** шифрование: `AES-256-OFB(DK, IV=AES_IV)` → base64.
5. **DevAuth** = `base64(HMAC-SHA256(masterKey, decimal(nonce) + decimal(unixNow) + ENCRYPTED_LocalAddr))`.
   ⚠️ Подписывается именно ШИФРТЕКСТ LocalAddr (фикс dh-p2p PR#29/#33, проверен на fw 6.7.30);
   подпись плейнтекста была багом dh-fwd.
6. XML-блок: `<CreateDate>`, `<DevAuth>`, `<Nonce>`, `<RandSalt>`, `<UserName>`.
   `getAuthAt` — вариант с фиксированным CreateDate: ретрансмиссии держат
   исходный timestamp, обновляют только Nonce/DevAuth/Laddr.

### 5.3 Info blob (123–145)

`DEVINFO_KEY = "kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf"` (32B AES-256),
`DEVINFO_IV = "MydvJw*Iw1w&i^kk"` (16B). Поле `Info` ответа `/info/device/<SN>`
= `base64(AES-256-OFB(JSON))`. **Происхождение: P2PDll.dll
CP2PClientImpl::parseDeviceInfo (docs/REVERSE.md §4.2 — документ утрачен,
см. §14).**

### 5.4 PTCP-фрейм (147–223)

24-байтный BE-заголовок + body:

```
"PTCP" | Rlid:u32 | Llid:u32 | Pid:u32 | Lmid:u32 | Rmid:u32 | body
```

- **Rlid** = наши отправленные байты (peer это ACKает своим Llid)
- **Llid** = наши принятые байты (кумулятивный ACK)
- **Pid**: SYNC-фрейм → `0x0002FFFF`, иначе `0x0000FFFF`.
  Семантика (docs/REVERSE.md §9.2, утрачен): младшие 16 бит = рекламируемое
  receive window, старшие = флаги (SYN=0x0002). dh-fwd всегда рекламирует
  полный window 0xFFFF — «мы дрейним немедленно». Устройство honour'ит flow
  control: уменьшающееся окно когда-то резало видеосессии.
- **Lmid** = локальный счётчик сообщений, **Rmid** = эхо peer Lmid.

**PTCPPayload** (realm-DATA, body type 0x10): 12-байтный подзаголовок
`length|0x10000000 :u32 | realm:u32 | pad(0):u32` + payload. Парсер:
`length &= 0xFFFF`, `len(body) == length`, `pad == 0` — иначе отброс.

### 5.5 DH HTTP-over-UDP парсинг (229–307)

`ParseDHResponse`: split по `\r\n\r\n`, статус-строка `VER CODE STATUS`,
headers `Name: value`, body → `parseXML` — разворачивает вложенность в
`body/path/to/tag` ключи. Код отсутствует → 0 (lenient, для infoFields).

### 5.6 UDP-обёртка (309–528)

`NewUDP(host, port, debug, prof)`:
- `udp4` на 0.0.0.0:0, **SIO_UDP_CONNRESET off** на Windows (иначе ICMP
  port-unreachable травит следующий read WSAECONNRESET)
- read buffer 4MB / write 1MB (камера льёт ~1280B сегменты на wire-rate)
- `bindIP`: фиктивный `net.Dial("udp4", host:port)` — OS выбирает egress-интерфейс
  без отправки пакета → финальная запись LocalAddr; деградация `127.0.0.1`
- `lastRecv = now` на создании

`Recv`: zero-copy (алиас rxBuf до следующего чтения — потребители обязаны
обрабатывать синхронно), WSAECONNRESET при активном таймауте — spurious,
продолжаем. `RecvFrom` — копирующий (STUN держит буферы между чтениями).

`Read(returnError, timeout)` — ждёт один DH HTTP ответ; без returnError код ≥400
→ error.

### 5.7 CSeq (564–585)

Глобальный мьютексный счётчик `cseq` (`nextCSeq`, smartpss). `nextCSeqFor(prof)`:
dmss → `uint32(getNonce())` — случайный знаковый int32; выделяется ОДИН раз на
логический запрос, ретрансмиссии реплеят (reqOpts.cseq).

### 5.8 WSSE digest (587–594)

`base64(SHA1(nonce + Created + "DHP2P:" + username + ":" + userkey))` — формула
общая для всех клиентов, различается только пара (username, userkey).

### 5.9 buildDHRequest (596–673) — сериализация запроса

Общий хвост: body непуст → `Content-Type: ` (ПУСТОЕ значение!) + `Content-Length: N`,
затем `\r\n` + body.

**smartpss (legacy)**:
```
DHGET /path HTTP/1.1\r\n
CSeq: N\r\n
[Authorization: WSSE profile="UsernameToken"\r\nX-WSSE: UsernameToken Username=..., PasswordDigest=..., Nonce=..., Created=...]
[x-pcs-request-id: ...]            ← если задан
[X-Version / X-Sversion / X-ToUType] ← если заданы (у smartpss их нет)
```

**dmss (appHeaderOrder)**:
```
NFGET /path HTTP/1.1\r\n
X-Version: 6.7.15\r\n
X-Sversion: 1.1.0\r\n
x-pcs-request-id: <32hex>\r\n
X-ToUType: Client/Dmss_Android\r\n
CSeq: <знаковый int32>\r\n
[auth]
```
warmup-режим (`/online/stun`): только X-ToUType, без auth и version-заголовков.
WSSE nonce тоже знаковый int32. Живой A/B: legacy-порядок на dmss-облаке →
403 DevPwd_InvalidDigest при байт-верной крипте body; app-порядок → 100/200 3/3.

### 5.10 Request/RequestEx (686–718)

verb из reqOpts или по body (пусто → GET-verb, непусто → POST-verb).
Отправка + опциональный `Read(false, RELAY_READ_TIMEOUT)`.

### 5.11 ACK-коалесинг (720–744)

`ackEvery = 1`, `ackDelay = 10ms`. `ScheduleAck` после каждого DATA-фрейма:
flush при `ackFrames >= 1` ИЛИ `>= 10ms` от прошлого ACK. Фактически при
ackEvery=1 ACKается каждый фрейм немедленно; delay-ветка мертва. Любой
исходящий фрейм несёт кумулятивный ACK в Llid, так что ожидание ничего не теряет.

### 5.12 ReadPTCP (746–881) — приём + ARQ-движок

Сначала дребеним `rcvReady` (восстановленные in-order фреймы прошлого вызова).

Приём: ParsePTCP, body копируется. Под мьютексом:
- `rmid = ptcp.Lmid`
- `peerAck` вперёд по ptcp.Llid; прунинг in-flight сегментов (`endSeq <= Llid`)
- **Jacobson/Karn RTT**: сэмпл только с сегментов, ACKнутых с первой попытки
  (`retries == 0`), валидных 0<s<60s: `srtt=(7srtt+s)/8`, `rttvar=(3rttvar+|d|)/4`,
  `rto=srtt+4rttvar`, clamp 250ms..60s
- **Fast retransmit**: 3 дубликата Llid подряд (`Llid == lastAckSeen`) →
  повторный отправка первого unacked сегмента (если retries<5)
- Контрольные фреймы (body пуст или body[0] != 0x10) **не занимают
  sequence-пространство** — возвращаются сразу
- DATA: `Rlid == rcvNxt` → in-order, `rcvNxt += len(body)`, дрейн contiguous
  из `rcvOoo` в `rcvReady`; `Rlid > rcvNxt` → буфер в rcvOoo (≤128) +
  немедленный dup-ACK; `Rlid < rcvNxt` → дубликат, re-ACK
- Таймаут → `context.DeadlineExceeded`

### 5.13 RequestPTCP (883–927)

SYNC-детект: body == `00 03 01 00` → Pid 0x0002FFFF, иначе 0x0000FFFF.
Счётчики: `ptcpSent += len(body)`, `ptcpID++`, DATA (не SYNC) → `ptcpCount++`,
сегмент в in-flight буфер (≤64): `seq = ptcpSent до, endSeq = ptcpSent после,
raw, sentAt`.

### 5.14 CheckRetransmit (929–959)

По всем in-flight: RTO = база (rto, floor 250ms) × `1<<retries` при повторах,
cap 60s; `now-sentAt >= RTO` и retries<5 → повтор, retries++, sentAt=now.

### 5.15 Прочее

`GetInvertedBytes` — НЕ ИСПОЛЬЗУЕТСЯ (инверсия инлайн в tunnel.go).
`isPeerSupportLinkSwitch(v)`: major ≥ 5 → link-switch поддерживается —
**зеркалит P2PDll.dll isPeerSupportLinkSwitchAndLocalP2P (0x18001D540)**.
Определяет 2024+ устройства → forceAppRelay + отключение пула.

---

## 6. core/tunnel.go (2960 строк) — ядро

### 6.1 Константы и таймеры (20–63)

```
BIND_TIMEOUT   = 10s        RETRY_ATTEMPTS = 3     RETRY_DELAY = 2s
CSEQ_BASE      = 100        CSEQ_STEP      = 1000   (RTSP keepalive cseq)
HEARTBEAT_TIMEOUT = 30s (var, --hb)   ← P2PDll CTcpRelayChannel::heartbeat 0x180016980 (30000 ms)
RELAY_READ_TIMEOUT = 15s (var)
rePunchSilence = 15s   rePunchEvery = 4s   silenceGiveUp = 45s
relayLookupTimeout = relayAgentTimeout = 3s        (dmss best-effort)
relayChannelFirstInterval  = 1200ms  ← SmartPSS CP2PLinkThroughRelay::onBindSuccess (sub_18004DFF0):
relayChannelRetransInterval= 2400ms     1. бюджет 10000ms (*(_QWORD*)(a1+5584)+10000)
relayChannelTotalBudget    = 10000ms    2. стартовый интервал 1200ms (кросс-континентальный RTT)
relayChannelMaxRetransmits = 4          3. экспонента v12 = 2*v12 до 2400ms
channelAckWindow  = 1800ms   ← DMSS capture: 100 Trying ~0.7s, 200 ~1.1s
channelMaxRetrans = 2
```

### 6.2 Ошибки и глобальное состояние (65–120)

`errDeviceNotFound` (404), `errDeviceRequireAuth` (403 при dtype=0),
`errAuthFailed` (403 при dtype>0), `isAuthError` — по errors.Is + подстроки.
`ForceAppRelay`, `ForceRelay`, `AutoReconnect` — из флагов.
`GlobalBytesUp/Down` — атомики трафика, `GetBytesStats/ResetBytesStats`.
`errPTCPAppFallback` — relay сыплет 0x13 heartbeat'ами вместо 0x17 токена.
`ptcpHeartbeat` = `13 00 00 00 00×8` (12 байт) — ОПРЕДЕЛЁН, но НЕ ОТПРАВЛЯЕТСЯ
(heartbeat'ы — чистые ACK-фреймы `RequestPTCP(nil)`).

### 6.3 Client + коалесинг (127–200)

`writeData`: аппенд в `pending`, flush при ≥16KB или через 2ms таймер;
`dataDown/dataUp` — счётчики зомби-детектора; глобальный down-счётчик.
`close()` — финальный flush + Close.

### 6.4 Tunnel struct (214–320) — состояние

Ключевое: `primary` (активный data-сокет, доступ ТОЛЬКО через
`setPrimary/getPrimary` под socksMu — race с reset()), `chanKey` (Type-1 ключ
для local-channel шага), `rePunch*` (recovery kit: пакет STUN-инициализации +
laddr/pub устройства), `generationWG` (все goroutines поколения),
`pools map[int]*poolState` + `poolTarget/poolExplicit`, `userMTU/segmentMax`,
`httpSem` (chan 3 — лимит одновременных port-80 BIND'ов, жив и без accel),
`accelResults map[uint32]chan []byte`.

`newTunnel`: noRelayAuth-профиль + pool>0 + не explicit → pool=0 (pre-bound
realms протухают на app-диалекте: capture BIND → 0x12 CONN → DATA ~6ms).
`reset()`: дрейн readerWG, свежие channels/maps, primary=nil, chanKey=nil,
rePunch kit очищен. `close()`: done, listeners, дрейн acceptCh, клиенты,
все три сокета.

### 6.5 channelRequest (489–699) — логический канал-запрос

**Идентичность фиксирована на konstruktion** (ретрансмиссии реплеят):
cseq (один раз), pcsID + clientID (dmss: `randomHex(16):<fwdPort>`),
identify (8 байт AID → hex), created (unix now), RandSalt, username.
**Крипта обновляется на каждый send** (`regenerate()`): Nonce, laddrEnc
(AES-OFB), WSSE digest (в buildDHRequest).

`identifyHex`: smartpss `%x` (без паддинга), dmss `%02x`.

`localAddrPrefixes`: все IPv4 интерфейсов, кроме loopback / 169.254.0.0/16 /
unspecified / равного bindIP. `buildLocalAddr`: CSV `prefix1,prefix2,...,bindIP:lport`;
нет префиксов → `bindIP,bindIP:lport` (дубликат parse-safe).

`body()`:
- dtype=0: `<IpEncrpt>true</IpEncrpt>` + плейнтекст LocalAddr
- dtype>0: `<IpEncrptV2>true</IpEncrptV2>` + **шифрованный** LocalAddr + authStr
- smartpss: LocalAddr сразу после encrypt-тега, затем `<version>5.0.0</version>`
- dmss (extendedBody): `<NatValueT>0</NatValueT><version>6.7.15</version><sVersion>1.1.0</sVersion><LocalAddr>…</LocalAddr><Pid>0</Pid><ClientId>…</ClientId>`
  — порядок элементов из DMSS-capture.

`channelSender.send(retransmit)`: retransmit → `regenerate()`, отправка с
reqOpts{cseq, pcsID}.

### 6.6 handshake() (709–717)

`establish()` + (dmss) goroutine `sendLocalChannel` со снапшотом
`localChannelStep` (ключ клонирован — не читает mutable state после запуска).

### 6.7 waitForPTCPToken (727–755)

Ждёт фрейм с body ≥13 байт (0x17-токен режется с [12:]). Body ≤12 или 0x13 →
дрейн, счётчик; 5 шортов → `errPTCPAppFallback` (relay не умеет токен).
Таймаут-чанки по 5s.

### 6.8 establish() (766–1356) — 4 фазы

**Фаза 1 — cloud discovery:**
- `mainRemote = NewUDP(mainServer)` (bindIP считается к main-серверу)
- warmup-проб (блокирующий RequestEx: smartpss `/probe/p2psrv` c auth; dmss
  `/online/stun` без) — дрейнит сокет, чтобы ответ warmup не отравил следующий read
- `/online/p2psrv/<SN>` → `body/US` = `<host>:<port>` устройства. Нет US →
  «not found on p2psrv».

**Фаза 2a — device probe:**
- `p2psrvRemote = NewUDP(US)`; `probeDeviceInfo`: `/probe/device/<SN>` (read)
  + `/info/device/<SN>` (отправка без read) + `Recv(65536, 15s)` → raw payload
- `applyDevicePorts`: JSON или DH-XML → поле `Info` → расшифровка SDK-ключами
  → httpport/privport/rtspport (валидация 1–65535), blob-поля перебивают top-level
- `resolveAutoSalt`: fail-closed матрица (см. 6.14)

**Фаза 2b — relay dispatcher:**
- smartpss: `/online/relay` → `body/Address` = dispatcher host:port (обязателен),
  запомнить в `relayDispatch`
- dmss (relayAgentOptional): короткий read 3s, тишина → лог + продолжение
  (приложение вообще не вызывает /online/relay — capture parity)

**Фаза 3 — p2p-channel:**
- `deviceRemote = NewUDP(mainServer)` — data-сокет через главное облако
- AID = 8 crypto-random байт; fwdPort = specs[0].Remote (для ClientId)
- `channelSender` → `send(false)`; `t.chanKey = key`
- channelRetransmit → `waitChannelEarlyAck(deviceRemote, xchg, logf, min(1800ms, 15s))`

**Relay agent alloc (параллельно рано-ack окну):**
- relayHost задан + dmss: `SetRemote(dispatcher)`, `/relay/agent`, read 3s —
  best-effort: `body/Token` + `body/Agent` (host:port)
- smartpss: `allocRelayAgent` (relay_resilience.go): семафор ≤6 глобально,
  кандидаты = dispatcher + один известный альтернативный, per-host backoff
  (3s << failures, cap 15s), read 4s; все молчат → fail попытки
- `startRelayAgent`: `SetRemote(agent)`, `/relay/start/<token>` с body
  `<body><Client>:0</Client></body>` ×3, read 1200ms до первого успеха

**Фаза 4 — device ack:**
- ранний ack есть → он; иначе `Read(true, 15s)`, code<200 → ещё read (100 Trying)
- 404 → errDeviceNotFound; 403 → по dtype; ≥400 → код+status
- `body/version` major ≥ 5 → forceAppRelay=true, poolTarget=0 (кроме --pool
  explicit) — «2024+ устройство»
- `body/LocalAddr`, `body/PubAddr`, `body/NatValueT`, `body/Policy`
- Type-1: device LocalAddr расшифровывается НАШИМ ключом + `body/Nonce` ответа
  (`getDec`)
- PubAddr отсутствует → fail (не паника на split)
- `deviceRemote.SetRemote(PubAddr)`

**Принудительный TCP (--R):**
- authStr (Type-1: getAuth с новым nonce, payload пустой)
- `waitTcpRelayChannel`: `POST /device/<SN>/tcprelay-channel` c `<body>authStr</body>`
  → 200 + `body/Agent` + `body/Token` → `attachTCPRelay` (dialTCPRelay c
  rport=specs[0].Remote). Ошибка → warning + fallback на UDP-путь.

**Принудительный relay (--relay / -r):** пропускает STUN целиком:
relay-channel ack → PTCP SYNC (`00 03 01 00`) → read sync → чистый ACK →
(если !noRelayAuth && !forceAppRelay && !ForceAppRelay) 0x17-токен:
`17 00×11` (12 байт), `waitForPTCPToken`; app-fallback → forceAppRelay.
`primary = mainRemote`.

**Гонка relay vs STUN (общий случай):**
- relay-горутина (если agentOK): как принудительный путь выше — relay-channel →
  SYNC → (токен 0x17)
- STUN-панч (главная горутина):

```
invAid[i] = ~aid[i]
eaddr = ~BE16(devPort) ‖ ~IPv4(devIP)          (6 байт)
stunInit (38 байт):
  FF FE FF E7 | cookie(4 crypto-rand) | transID(12 crypto-rand)
  7F D5 FF F7 | invAid(8) | FF FB FF F7 FF FE | eaddr(6)
```

- sendBurst: LocalAddr устройства (из расшифрованного ответа), PubAddr,
  и sweep `devPort + off` для off = step..64 с шагом peerValueT (если 1<т≤8)
  иначе 1 — parity SmartPSS на симметричных NAT
- Цикл: deadline 3s, read 250ms, ≤8 попыток с ретрансмитом burst'а
- Ответ `FE FE…` → lock deviceRemote на источник → stunChan
- Кросс-инициализация устройства (`FF FE…`) → lock + ответ 3×:
  `FE FE FF E7 | peer-cookie [4:8] | peer-transID [8:20] | 7F D6 FF F7 |
  invAid | [FF FB FF F7 FF FE | peer-eaddr [34:40]]` → stunChan
- confirm (24 байта): `FE FE FF F3 | cookie | transID | 7F D6 FF F7 | invAid`
- `activateDirect`: confirm ×5, sleep 100ms, drain 200ms, SYNC
  (`00 03 01 00`), `ReadPTCP(2s)` (ошибка НЕ фатальна — продолжаем на
  пробитом канале), `storeRePunch`, `primary = deviceRemote`. Прямой путь
  всегда «SYNC only, no link-switch 0x17/0x19 (pure P2P)»
- select-гонка: relayDone первым → `primary = mainRemote` (STUN дрейнится в
  фоне, не перехватывает); stunChan первым → activateDirect. Оба мертвы →
  Policy содержит `tcprelay` → TCP fallback; иначе fail.

### 6.9 waitRelayChannelAck (1455–1541)

`/device/<SN>/relay-channel` c body `<body>authStr<agentAddr>host:port</agentAddr></body>`,
CSeq по диалекту. Отправка: SetRemote(main) → send → SetRemote(agent).
Цикл ≤4 ретрансмитов: интервал 1200ms → ×2 → cap 2400ms; read до границы
интервала; **100 Trying поглощается** (sub_180049B20 parity: v5==100 → continue);
200 → isPeerSupportLinkSwitch(version) ещё раз → nil; ≥400 → reject; бюджет
10s общий → «wait peer timeout».

### 6.10 waitChannelEarlyAck (1543–1604)

Окно 1800ms, слоты = window/3 (~600ms): ре-сенды на ~0.6s/1.2s (capture ~0.55/1.1s),
максимум 2. Любой ≥400 — ТЕРМИНАЛЬНЫЙ ответ независимо от identity (403-ки
несут server-генерированный pcs-id, никогда не совпадёт). 1xx/2xx:
dmss корреляция по pcs-id АЛОНЕ (сервер иногда пишет `CSeq: 0` на валидные
ответы); smartpss — по CSeq. 1xx → ждём финальный. Всё отброшенное — логируется
с классом (datagramClass: PTCP/STUN/status line/quoted head).

### 6.11 local-channel шаг (1644–1701)

Снапшот → отдельный сокет → dmss: GET `/device/<SN>/local-channel`,
Type-1: `<body>getAuth(...)</body>` — DevAuth покрывает только nonce+created
(БЕЗ LocalAddr!). Read 2s. Best-effort, ошибки логируются.

### 6.12 ptcpHandshake (1705–1744) — ⚠️ МЁРТВЫЙ КОД

SYNC → `19 00×11 ‖ signToken` → ждём body[0]==0x1A → `1B 00×11` → ждём
пустой body. Никем не вызывается, но документирует 0x19/0x1A/0x1B
AUTH_REQ/AUTH_RESP/AUTH_FINAL обмен. **Отправка 0x17 в establish — 12 нулей
после 0x17, БЕЗ signToken; полный 0x17→0x19-токен путь в dh-fwd не работает.**

### 6.13 serve() (1754–1875)

- Port overrides: blob httpport/privport/rtspport перезаписывают remote 80/37777/554
- Listeners `127.0.0.1:local`, 5 попыток × 200ms; ephemeral → фактический порт
- okPort в реестр; прогресс-бар Done; uptime tracker; direct/relay печать
- Горутины UDP: readLoop(deviceRemote) + readLoop(mainRemote) + heartbeatLoop(5s)
  + zombieWatchdog + poolKeeper на каждый порт
- Горутины TCP: touReadLoop + touHeartbeatLoop(6s)
- Главный select: done → readerWG.Wait → failure(); acceptCh → handleBind

### 6.14 readLoop (1880–1938)

Idle-читалки по 250ms. На таймауте: CheckRetransmit; если это primary и
молчание >45s → fail (rebuild через runWithRetries); >15s → tryRePunch
(re-отправка сохранённого STUN-инита на laddr+pub устройства, rate-limit 4s,
затем чистый ACK). Не-PTCP датаграмма (опоздавший ack, 100 Trying, мусор) —
ЛОГ + игнор (живой кейс 2026-09-13); isTransportDead → fail.

### 6.15 Служебные циклы

`heartbeatLoop` (5s): mainRemote (если не primary) — чистый ACK; primary —
CheckRetransmit + чистый ACK; RTSP-клиентам порта 554, idle >25s — инжект
`OPTIONS * RTSP/1.0\r\nCSeq: N\r\n\r\n` (cseq от CSEQ_BASE+1000×client).

`touHeartbeatLoop` (6s): writeKeepalive(0); RTSP-keepalive то же.

`touReadLoop`: readFrame(10s); heartbeat-молчание >HEARTBEAT_TIMEOUT → fail;
DATA → клиенту; SYN → writeAck; ACK/KA/SRV — liveness; прочее — лог.

`zombieWatchdog` (3s): только если primary НЕ deviceRemote. Зомби = весь relay
отдал 0 байт всем клиентам И существует клиент с up>0, down==0, age>12s →
forceAppRelay=true + fail(errZombieRelay) — rebuild в app-диалекте.

### 6.16 Realm pool (2077–2191)

`popRealm/pushRealm/dropRealm` под poolMu. `preBindRealm`: BIND 0x11 (fresh
random realm), sleep 3ms под bindReqMu, wait ≤10s → push. `poolKeeper` (250ms):
spawn = target − queue − inflaint, каждый spawn — goroutine preBindRealm.

### 6.17 handleBind (2196–2303)

- port 80 → httpSem (3 слота) — **работает и при выключенном accel**
- UDP + pooled realm есть → addClient мгновенно (без BIND-раундтрипа)
- BIND-пакет 20 байт: `[0]=0x11, [4:8]=realm BE32, [12:16]=remotePort BE32,
  [16]=0x7F, [19]=0x01` — выглядит как обрывок `127.0.0.1` ([16]=0x7F, [19]=0x01)
- send, sleep 10ms (под bindReqMu), тикер 400ms ретрансмит, таймер 10s
- 0x12 CONN → addClient — **клиент подключается только ПОСЛЕ подтверждения
  realm** (capture: DATA до BIND → устройство отвечает немедленным 0x12 DISC)
- fail таймаут → закрыть конн, освободить httpSem
- TCP-путь: addClient + touBuildSyn(realm, port) — realm = TOU session

### 6.18 Клиенты и данные (2319–2413)

`addClient`: Client{cseq: CSEQ_BASE (инкремент CSEQ_STEP на клиента)},
goroutine clientReader. `clientReader`: 16KB read → dataUp/GlobalUp →
writeRealmData; ошибка → DISC-пакет `12 00×3 ‖ realm ‖ 00×4 ‖ "DISC"` (16 байт:
[0]=0x12, [4:8]=realm, [12:16]="DISC") → delClient.
`writeRealmData`: чанки по segmentMax → PTCPPayload(Realm) → RequestPTCP,
либо tou writeData.

### 6.19 routePTCP (2417–2492)

- Пустой body → зеркальный чистый ACK
- `0x00` SYNC → ACK
- `0x10` DATA → ParsePTCPPayload → accel-канал (спит) → клиенту writeData
- `0x12`: realm = BE32(body[4:8]); DISC ⟺ len≥16 && body[12:16]=="DISC";
  ждущий BIND → CONN (close ch) / DISC (dropRealm); **дубликаты 0x12 CONN НЕ
  закрывают активных клиентов**; DISC на активного → close+del («DVR DISC»)
- `0x13` heartbeat — liveness через lastRecv, без действий
- `0x0a` — **no-op** (комментарий: «flow-control / ping frame from device or
  relay agent»)
- default: лог + эвристика — body ≥12 → realm=BE32(body[4:8]), payload=body[12:],
  если ≤4096 и клиент существует → доставить как данные

### 6.20 Recovery + retry (2494–2648)

`storeRePunch/tryRePunch` — см. 6.14.
`runWithRetries`: терминальные (404/auth/no listeners) — только если не было
коннекта и без --reconnect; wasConnected = hasServed || attempt>5s; стабильная
сессия >30s сбрасывает счётчик попыток; реконнект-задержка = attempt×2s cap 10s;
иначе 3 попытки с RETRY_DELAY 2s. Каждый цикл — `reset()` (новое поколение).

### 6.21 Info blob утилиты (2652–2922)

`infoFields` (JSON `{...}` → decodeInfoJSON tolerant, иначе DH-XML flatten).
`probeDeviceInfo`. `applyDevicePorts`. `resolveAutoSalt` — матрица fail-closed:
required = (autoSalt && dtype>0 && salt==""); явный salt / dtype=0 →
возврат ДО декодирования (никогда не перетирается). `randsaltFromInfo` —
расшифровка + `randsalt` поле. `queryDeviceInfo` (--info): US-сокет → probe →
info → печать devP2PVersion, DevVersion, Info plain (sorted) + подсказка
с `-s`. `isMostlyPrintable` 90%.

### 6.22 accel-диспатч (2924–2960)

`dispatchAccelData`: канал в accelResults → копия payload, отправка с grace
500ms / t.done — «никогда не терять: фрейм уже ACKнут PTCP'ом, дроп перманентен»
(живой кейс 2026-10-08: ext-all.js 1493814/1497654, три потерянных 1280B).
`dispatchAccelDisc` — nil в канал. Оба живы, но при выключенном accel
accelResults всегда пуст → всегда false.

---

## 7. core/tcp_relay.go (262 строки) — TOU-канал

Таймауты: dial 4s, bind 15s, ack 15s, frame 10s, write 10s, keepalive 6s
(`30s/5` — P2PDll 0x1800169D8; должен быть < HEARTBEAT_TIMEOUT — иначе
keepalive-тишина убивала каналы, аудит 2026-09-13).

`dialTCPRelay`: TCP dial → NoDelay → **(A1) bind**: `POST /tcprelay/client-bind`
c `<body><Token>…</Token></body>`, verb и CSeq — по профилю (DHPOST/счётчик
для smartpss), buildDHRequest на том же сокете → readHTTPResponse (drain
Content-Length <64KB чтобы не рассинхронить TOU-стрим) → **(A2) SYN** с
random uint32 session + rport → ждём ACK (KA/SRV поглощаются).

`readFrame`: bufio.Peek(4) → touFixedLen или DATA `12 + BE16(head[2:4])`,
cap 0x10000 → Peek(need) → Discard → parseTouPacket → markRecv.

**A1/A2 — явно помеченные предположения из дизассембла (docs/REVERSE.md
Part III, утрачен) — первые кандидаты на сверку с IDA-псевдокодом.**

---

## 8. core/tou.go (160 строк) — TOU-фрейминг

Байт-в-байт из P2PDll.dll (parseTouPacket 0x180018660, sendSyn 0x1800158B0,
sendAck 0x180015B10):

```
byte 0 = (version << 4) | type, version == 0x1 → старший ниббл 0x10
byte 1 = flags/reserved (наблюдается 0x00)
типы: 0x00 DATA (12B hdr + BE16 len @2, session @4:8)
      0x01 SYN   20B: session @4:8, port BE16 @14:16, 127.0.0.1 @16:20 (7F 00 00 01)
      0x02 ACK   16B: session @4:8, value BE32 @12:16
      0x03 KA    12B: session @4:8
      0x04 SRV   12B: session @4:8
touMaxPacketLen = 0x10000 (граница [ch+0x338] в parseTouPacket)
```

`touBuildService` — НЕ ВЫЗЫВАЕТСЯ (наблюдённый в SDK secondary service).
SYN без порта → нули в [14:20] (port 0 → не заполнять [16]/[19]).

---

## 9. core/relay_resilience.go (296 строк)

`isTransportDead`: timeout → false; маркеры контентных ошибок (`packet too
short`, `invalid magic/padding/length`, `invalid tou message`) → false; всё
остальное (closed, ICMP, out-of-fd) → терминально.

Глобальный семафор relay-alloc ≤6 (`RelayAllocLimit`). Dispatcher-кэш ≤8
адресов: `penalize` = 3s << failures cap 15s, `forgive` при успехе,
`nextTo` — первый не в backoff.

`allocRelayAgent`: кандидаты = [dispatcher, один alt], по каждому: backoff
(последний кандидат — ждём урезанный до 2s), `/relay/agent` read 4s, молчание
→ penalize → следующий. Успех → Agent host:port + Token.

`startRelayAgent`: `/relay/start/<token>` c `<body><Client>:0</Client></body>`
×3, read 1200ms.

`zombieWatchdog` — см. 6.15.

---

## 10. core/http_accel.go (523 строки) — ⚠️ ВЫКЛЮЧЕН

Вызов из handleBind закомментирован (tunnel.go ~2208: «HTTP accelerator
disabled: direct PTCP streaming for port 80»). Вся машина (probe Range 0-0,
кэш размеров, 5 воркеров, чанки 300KB, retry чанка, короткое тело = ошибка,
`Contene-Type` — опечатка прошивки Dahua в fallback, mimeByExt, replayConn)
живёт, но спит: accelResults никто не заполняет, dispatchAccelData всегда
false. Держать в голове при реверсе: **на DLL не отображается, это чистая
клиентская оптимизация dh-fwd**.

Константы: threshold 128KB, workers 5, chunkLimit 300KB, chunkTO 30s,
dispatch-grace 500ms.

---

## 11. core/mtu.go (244 строки)

```
dataSegmentMax  = 1280   ← Dahua CProxySession (0x18012C71C / 0x180024480)
wireOverheadIPv4 = 64    (20 IP + 8 UDP + 24 PTCP + 12 PTCPPayload)
wireOverheadIPv6 = 84
minSegmentMax   = 256
```

`resolveSegmentMax`: userMTU>0 → mtu−overhead (если mtu≥576, иначе как есть),
clamp 256..1280; без флага — **всегда 1280** (KISS, без стартовых проб;
PMTUD живёт только в --test-mtu). `probePathMTU`: padded DHGET `/probe/p2psrv`
c X-Pad, DF-бит, кандидаты 1500/1420/1280/1200, ответ «200 OK» = прошёл.

---

## 12. Вспомогательные файлы

**ui.go (292):** UI-писатель (один writer-goroutine, канальная сериализация) —
создаётся через NewUI, но `newPortRegistry(serial, specs, nil)` всегда с nil →
UI фактически спит. ConnectProgress: 24-ячейки бар, 7 фаз с весами [4,2,3,4,4,3,4]
(sum 24), в-место-перезапись `\r` + паддинг до 110 колонок. FormatBytes,
StartUptimeTracker (1s тикер, uptime + ↑/↓ трафик, финальная строка на done).

**logger.go (59):** `dh-fwd.log` append, баннер сессии, строки `[время] msg`;
без файла — fallback в stdout.

**updater.go (225):** GitHub releases/latest, TO 2s, UA `dh-fwd/<ver>`;
isNewerVersion с ZeroVer-маппингом 0.1→[2,5,0] против v2.x-тегов; asset-имена
win/linux × x64/arm64; selfUpdate: temp-файл рядом с exe, на Windows —
свап через `.old` с rollback.

**udp_windows.go / udp_other.go:** udpControl (SIO_UDP_CONNRESET off),
isConnReset, setSocketDF (Windows: IP_DONTFRAGMENT=14; прочие ОС — заглушка!).

**vt_windows.go / vt_other.go:** ENABLE_VIRTUAL_TERMINAL_PROCESSING на
stdout/stderr (ANSI-цвета в Windows-консоли).

---

## 13. Сводные таблицы

### 13.1 Все wire-опкоды PTCP body[0]

| Опкод | Значение | Отправка dh-fwd | Приём dh-fwd |
|---|---|---|---|
| 0x00 | SYNC `00 03 01 00` | да (Pid 0x0002FFFF) | зеркальный ACK |
| 0x0a | ping / flow control | нет | **no-op** |
| 0x10 | realm DATA (PTCPPayload) | да | парс → клиент / accel |
| 0x11 | BIND (20B) | да | — |
| 0x12 | CONN/DISC (realm @[4:8], "DISC" @[12:16]) | DISC при закрытии клиента | CONN → bindWait; DISC → dropRealm/close |
| 0x13 | heartbeat | нет (чистые ACK) | no-op (liveness) |
| 0x17 | token auth req (12 нулей) | да, relay-путь | waitForPTCPToken |
| 0x19/0x1A/0x1B | AUTH_REQ/RESP/FINAL | **мёртвый код** | — |

### 13.2 DH HTTP endpoints

| Endpoint | Verb | Где |
|---|---|---|
| `/probe/p2psrv` | GET | smartpss warmup (auth) |
| `/online/stun` | GET | dmss warmup (без auth) |
| `/online/p2psrv/<SN>` | GET | резолв US |
| `/probe/device/<SN>`, `/info/device/<SN>` | GET | US-сокет |
| `/online/relay` | GET | dispatcher |
| `/relay/agent` | GET | agent+token |
| `/relay/start/<token>` | POST `<body><Client>:0</Client></body>` | старт |
| `/device/<SN>/p2p-channel` | POST | канал |
| `/device/<SN>/relay-channel` | POST `<agentAddr>` | привязка агента |
| `/device/<SN>/tcprelay-channel` | POST | TCP-путь |
| `/device/<SN>/local-channel` | GET | dmss app-parity |
| `/tcprelay/client-bind` | POST `<Token>` (по TCP) | TOU attach |

### 13.3 Таймеры — происхождение

**Из P2PDll (адрес известен):**
- HEARTBEAT_TIMEOUT 30s — CTcpRelayChannel::heartbeat 0x180016980
- TCP keepalive 6s — 0x1800169D8 (30/5)
- relay-channel 1200/2400/10s/4 — sub_18004DFF0
- 100 Trying absorb — sub_180049B20
- TOU framing + 0x10000 cap — 0x180018660 / 0x1800158B0 / 0x180015B10 / [ch+0x338]
- dataSegmentMax 1280 — CProxySession 0x18012C71C / 0x180024480
- isPeerSupportLinkSwitch (major≥5) — 0x18001D540
- DEVINFO_KEY/IV — CP2PClientImpl::parseDeviceInfo
- CPhonyTcp: in-order reassembly (processReceiver), fast retransmit (строка 89),
  retransAckSegment

**Из captures (2026-09-06 DMSS APK 2.6.20 / 2026-09-13 / 2026-10-08):**
- channelAckWindow 1800ms / 2 ре-сенда (ре-сенды ~0.55/1.1s)
- appHeaderOrder + randomCSeq + extendedBody порядок элементов
- localChannel шаг, noRelayAuth (BIND → CONN → DATA ~6ms)
- relayAgentOptional (Dolynk dispatcher молчал 17s ×3)
- DATA только после подтверждённого BIND (иначе 0x12 DISC)
- DMSS Created с числовым offset, WSSE nonce знаковый

**Изобретение dh-fwd / поведенческий паритет (НЕ в DLL):**
- rePunch 15s/4s/45s, silenceGiveUp
- zombie watchdog 12s/3s
- dispatcher backoff 3s/15s, alloc limit 6, alloc TO 4s
- bind ticker 400ms, sleep 3ms/10ms, BIND_TIMEOUT 10s
- readLoopIdleTimeout 250ms, heartbeat тик 5s
- ackEvery=1/ackDelay=10ms
- RTO floor 250ms / cap 60s / Jacobson 7-8 3-4 / 3 dup-ACK / retry cap 5 /
  in-flight 64 / OOO 128
- RTSP OPTIONS keepalive 25s, CSEQ_BASE/STEP
- коалесинг клиента 2ms/16KB
- STUN burst: 3s deadline / 8 попыток / sweep окно 64 / шаг peerValueT / confirm ×5 / ответ 3×
- runWithRetries вся логика, порт-оверрайды из blob, accel (спит)

---

## 14. Мёртвый / спящий код

| Что | Где | Статус |
|---|---|---|
| `ptcpHandshake` (0x19/0x1A/0x1B) | tunnel.go:1705 | не вызывается |
| `httpAccelHandler` + вся accel-машина | http_accel.go | вызов закомментирован |
| `GetInvertedBytes` | helpers.go:968 | инлайн-инверсия в tunnel.go |
| `touBuildService` | tou.go:90 | не вызывается |
| `peekConn` | http_accel.go:516 | не используется |
| UI/NewUI/uiCmd* | ui.go | reg.ui всегда nil |
| `ptcpHeartbeat` (0x13) | tunnel.go:116 | определён, не отправляется |
| `probePathMTU` | mtu.go:31 | только из RunMTUTest |
| `udp_other.setSocketDF` | udp_other.go:19 | заглушка (DF только Windows) |
| docs/REVERSE.md | ссылки в 7 файлах | **файла нет и в git не было** |

---

## 15. Чек-лист сверки с P2PDll (куда смотреть в IDA в первую очередь)

Каждый пункт — место, где dh-fwd действует по интерпретации/поведению и
может разойтись с DLL:

1. **0x0a-фреймы** — dh-fwd игнорирует. Что делает DLL? Настоящий flow-control?
   Если DLL уменьшает окно по 0x0a — у dh-fwd окно всегда 0xFFFF, отсюда
   возможные расхождения с поведением устройства под нагрузкой.
2. **Pid window** — как DLL вычисляет рекламируемое окно (комментарий dh-fwd
   упоминает count-based shrinking window, который резал видеосессии).
   Проверить формат: старшие 16 бит = флаги (SYN=0x0002), младшие = окно?
3. **0x17 токен** — dh-fwd шлёт `17` + 11 нулей и НЕ читает содержимое ответа.
   DLL: какой payload в 0x17, что приходит в ответе, что за signToken в 0x19?
   Живой relay-агент сейчас распознаётся по «5 шортов/heartbeat-спама».
4. **0x19/0x1A/0x1B** — мёртвый код в dh-fwd; у DLL это рабочий AUTH-обмен
   после SYNC на relay-пути. Восстановить из псевдокода полностью.
5. **BIND-пакет** — `[16]=0x7F, [19]=0x01`: это 127.0.0.1 в [16:20]?
   dh-fwd оставляет [17][18] нулями. Сверить полный layout 20-байтного BIND'а
   (что в [8:12]?).
6. **DISC-пакет** — "DISC" ASCII на [12:16]. Есть ли CONN-ответ от клиента?
   dh-fwd на 0x12 CONN просто закрывает bindWait.
7. **Heartbeat 0x13** — dh-fwd НЕ шлёт 0x13 (только чистые ACK). DLL шлёт
   0x13 с периодом? Содержимое body?
8. **STUN-константы** — `FF FE FF E7`, `7F D5 FF F7`, `7F D6 FF F7`,
   `FF FB FF F7 FF FE`, confirm `FE FE FF F3`, конструкция cross-response,
   повторы ×3/×5, sweep-окно 64 с шагом NatValueT. Всё унаследовано от
   dh-p2p — сверить с реальным punch-кодом DLL.
9. **RTO/ACK-движок** — floor 250ms, cap 60s, Jacobson коэффициенты, 3 dup-ACK,
   retry cap 5, in-flight 64, OOO 128: у CPhonyTcp свои значения — снять их.
10. **Контрольные фреймы вне sequence** — dh-fwd считает, что только 0x10 ест
    sequence-пространство (Rlid). Проверить в CPhonyTcp::processReceiver.
11. **TOU (A1)/(A2)** — bind по тому же TCP-сокету, SYN-параметры, ACK-значение.
12. **/relay/start body** `<Client>:0</Client>` и **relay-channel** `<agentAddr>`
    — байтовый паритет?
13. **ptcpID/Lmid/Rmid** — семантика счётчика сообщений и эха; dh-fwd
    инкрементит на каждый отправ (включая чистые ACK), Rmid = последний
    принятый Lmid.
14. **Keepalive 6s** — подтвердить 0x1800169D8 (30/5) и что значение в DLL
    относится именно к TOU-каналу.
15. **devP2PVersion / link-switch** — что ещё делает DLL при major≥5 кроме
    выключения token-auth (dh-fwd: forceAppRelay + pool off)?

---

## 16. Живые инциденты, зашитые в код (контекст для новых фиксов)

- 2026-09-06: legacy-заголовки на dmss-облаке → 403 DevPwd_InvalidDigest;
  Dolynk relay dispatcher молчал 17s ×3; слайс [12:4] паника от 4-байтного SYNC-ack.
- 2026-09-08: nil-panic clientReader после reset (породил setPrimary/getPrimary).
- 2026-09-13: late DH ack на data-сокете убивал здоровые туннели (parse error ≠
  смерть сокета); PubAddr иногда отсутствует в ack; easy4ip alloc-флап
  (70% аллоков мимо) → resilience-модуль.
- 2026-10-08: ext-all.js 1493814/1497654 — потерянные PTCP 1280B фреймы
  (accel-грейс 500ms, короткое тело = ошибка чанка).

---

## 17. P2PDll.dll (SmartPSS Lite, декабрь 2022) — карта для IDA

Файл: `C:\Program Files\SmartPSSLite\P2PDll.dll`, x64, 1 899 352 байт,
timestamp 1615383425 (собрана 2021-03-10), preferred ImageBase **0x80000000**.
Секции: .text RVA 0x1000 (vsize 0x126000), .rdata 0x127000 (0x64600),
.data 0x18C000, .pdata 0x1B9000, .rsrc 0x1D0000, .reloc 0x1D1000.

⚠️ **Адреса из комментариев dh-fwd (0x180016980 и т.п., base 0x180000000) к
этой сборке НЕ применимы**: например их 0x18012C71C → RVA 0x12C71C попадает
в .rdata (зона строк), где кода быть не может. REVERSE.md писался по другой
сборке — все функции ищем заново по строкам/RTTI. RVA ниже стабильны.

### 17.1 Экспорты (весь публичный API — 8 функций)

| RVA | Экспорт |
|---|---|
| 0x1510 | P2P_Init |
| 0x15B0 | P2P_UnInit |
| 0x1630 | P2P_Connect |
| 0x1680 | P2P_Disconnect |
| 0x1770 | P2P_QueryServerStatus |
| 0x1780 | P2P_GetDeviceInfo |
| 0x1810 | P2P_DeviceStatus |
| 0x1820 | P2P_QueryChannelStatus |

Тонкие обёртки над CP2PClientImpl. Вход в живой код — P2P_Connect.

### 17.2 Строковые якоря ( RVA / VA при base 0x80000000 )

| Якорь | RVA | VA | Что искать рядом |
|---|---|---|---|
| `p2p-channel` | 0x12C5B0 | 0x8012C5B0 | блок путей-суффиксов |
| `relay-channel` | 0x12C5C0 | 0x8012C5C0 | » |
| `local-channel` | 0x12C5D0 | 0x8012C5D0 | » |
| `tcprelay-channel` | 0x12C660 | 0x8012C660 | » |
| `DHGET` | 0x12C8C4 | 0x8012C8C4 | сериализация запроса |
| `DHPOST` | 0x130048 | 0x80130048 | » |
| `UsernameToken` | 0x1301FD | 0x801301FD | WSSE-заголовок |
| `DevAuth` | 0x130DE8 | 0x80130DE8 | Type-1 auth-блок |
| `RandSalt` | 0x130E18 | 0x80130E18 | » |
| `Login to ` | 0x1331B3 | 0x801331B3 | MD5 master key (getDeriveKey) |
| `IpEncrpt` ×2 | 0x1322D8, 0x132320 | 0x801322xx | оба варианта body (v1/v2) |
| `PTCP` (магия) | 0x129973 | 0x80129973 | CPhonyTcp framing |
| `MydvJw*Iw1w&i^kk` (DEVINFO_IV) | 0x12B5C0 | 0x8012B5C0 | parseDeviceInfo |
| `kRjmsUB&ezmdGLL67H…` (DEVINFO_KEY) | 0x12B5D8 | 0x8012B5D8 | » |
| `2z52*lk9o6HRyJrf` (AES_IV) | 0x12B600 | 0x8012B600 | LocalAddr-OFB |

### 17.3 RTTI-имена классов (кластеры в .rdata)

| Класс | первый hit RVA |
|---|---|
| CTcpRelayChannel | 0x129BF0 |
| CProxySession | 0x12BCF4 |
| isPeerSupportLinkSwitch (имя ф-ции) | 0x12AFC1 |
| CPhonyTcp | 0x12DD8C |
| CP2PClientImpl (+parseDeviceInfo 0x12EB0C) | 0x12E5FC |
| CP2PLinkThroughRelay | 0x130474 |

### 17.4 Отсутствующие литералы — СНЯТО 2026-10-24 (второй проход)

Первый проход промазал: эндпоинты лежат с трейлинг-слэшем и в формат-строках.
Полный список (IDA-адреса, base 0x180000000):

| Строка | Адрес |
|---|---|
| `/online/relay` | 0x18012C5E0 |
| `/relay/agent` | 0x18012C5F0 |
| **`/relay/bind/`** — dh-fwd НЕ шлёт | 0x18012C600 |
| `/relay/start/` | 0x18012C610 |
| **`/relay/begin`** — dh-fwd НЕ шлёт | 0x18012C620 |
| **`/relay/unbind/`** — dh-fwd НЕ шлёт (cleanup!) | 0x18012C630 |
| `/online/stun` | 0x18012C640 |
| **`/p2p/stun/probe`** — dh-fwd НЕ шлёт | 0x18012C650 |
| `/probe/p2psrv` | 0x18012CFA8 |
| `/probe/device/` | 0x18012E8C0 |
| `/online/p2psrv/` | 0x18012E9B0 |
| `/info/device/` + формат `DHGET /info/device/%s HTTP/1.1` | 0x18012ED80 / 0x18012EF98 |

### 17.5 Внутренний инвентарь (~350 функций)

Полный список с якорями — **docs/p2pdll-functions.md** (имя-строка лога = адрес
xref'а). Ключевые классы сверх известных: CMultiStunClient (calculateValueT!),
CICESession (sendSynMessage/sendSynAckMessage/sendAckMessage), CStunMSG
(getTurnPeer — TURN!), CP2PLinkThroughLocal (LAN-путь!), CP2PLinkThroughTcpRelay,
CDevicePasswordAuth, CPhonyTcpTransport, CTimeOffset (updateOffset — синхрон
времени), CFifoBuffer/CReceiverBuffer/CUdpSendBuffer, CPortResource,
Dahua::Component (clientLogin / clientCreateInternal — фабрика инстансов).

### 17.6 Карта процесса коннекта (по якорям логов)

```
P2P_Connect (экспорт RVA 0x1630)
 └► Component::clientCreateInternal      якорь 0x18013D5F0
     └► Component::clientLogin           якорь 0x18013C360
         └► CP2PClientImpl (P2PClient.cpp) — connect-оркестратор
             ├► CP2PClientImpl::sendInfoDeviceReq        0x18012E748  (/info/device)
             ├► CP2PSDKChannelClient::sendRequest        0x180132CC8  (p2p-channel)
             └► ответ → CP2PLinkThroughClient::onP2PResponse 0x180132270
                 └► выбор стратегии (Policy):
                     ├► CP2PLinkThroughLocal::onChannelInit   0x180131578  (LAN, dh-fwd нет)
                     ├► CP2PLinkThrough::startStun            0x180132760
                     │    └► startIce                         0x1801328B0
                     │        ├► CMultiStunClient::onWaitNatInfo     0x18012C7E0
                     │        │    └► calculateValueT                0x18012CC20
                     │        ├► CStunClient::sendBindingRequest     0x180137B20
                     │        └► CICESession::sendSyn/SynAck/Ack
                     ├► CP2PLinkThroughRelay::onChannelInit  0x1801312C8
                     │    ├► onResponseGetRelay             0x180130C90  (/online/relay)
                     │    ├► onResponseRelayAgent           0x180130D88  (/relay/agent)
                     │    ├► onResponseRelayStart           0x180130A90  (/relay/start)
                     │    ├► onReponseRelayChannel          0x180130BC8
                     │    ├► onBindSuccess                 0x180131218  (PTCP sync/token)
                     │    └► onResponseUnbind              0x180130560  (/relay/unbind)
                     └► CP2PLinkThroughTcpRelay::onChannelInit 0x180131B18
                          ├► onGetAgentSuccess → onWaitConnectAgent → onWaitAgentBind
                          └► CTcpRelayChannel::parseTouPacket  0x18012A328

Data path: CPtcpChannel (connect/heartbeat/onConnect) → CPhonyTcp::
  processReceiver 0x180133DA8, retransAckSegment 0x180133F78 (ARQ!)
Proxy-слой: CProxyChannel — sendSyn/sendAck/sendData/sendKeepAlive/
  sendPause 0x18012AC70 / sendResume 0x18012AD88  ← flow control (0x0a?)
  CProxyChannelClient::procLinkSwitch 0x18012B720 (live link migration)

Крипта: kdf256 0x18012CE40, CDevicePasswordAuth::encryptLocalIpAddr
0x1801330E8, aesOfb265Encrypt2Str/aesOfb265StrDecrypt, CMd5::hex, CSha1::final.
```

---

## 18. Сверка с DLL — протокол находок (IDA-псевдокод, 2026-10-24)

### 18.1 CPhonyTcp::setOption (sub_180062580)

Опции PTCP-объекта: **0** → bool-флаг (+252, инверсия: val==0→true), **1** →
u32 (+256), **2** → resizeReceiveBuffer, **3** → resizeSendBuffer (ёмкость в
БАЙТАХ — dh-fwd считает in-flight сегментами, ≤64), **6** → reject («phony
tcp only support packet mode»), прочее unsupported. Опции из
CPtcpChannel::connect (8,0,2,5=10) идут через ДРУГОЙ враппер (setsockopt-style,
значение по указателю) — сокет-уровень, не PTCP; требует Socket-враппер.

### 18.2 parseOptions/applyOption (sub_1800664F0) — SYNC РАСШИФРОВАН

Тело SYNC = флаги-байт + TLV-опции (как TCP): **0**=end, **1**=NOP,
**2**=MSS (**DLL не поддерживает MSS от пира** — лог подтверждает),
**3**=window scale, len=1, значение=shift-байт (+148).

Наш `00 03 01 00` = флаги 0x00 + опция `03 01 00` (window scale, shift 0) —
корректно СЛУЧАЙНО (наследие dh-p2p). Последствия:
- приём в dh-fwd — байтовое сравнение (tunnel.go:1712) — хрупко: пир может
  прислать scale≠0 или MSS → ложный sync mismatch;
- пир без window-scale → DLL фиксирует окно 0xFFFF (поля 56/232), scaling
  off (+72=0) — подтверждает Pid: младшие 16 бит = окно; наш вечный 0xFFFF =
  режим «без scaling» ✓;
- DLL умеет динамическое окно при согласованном scaling — dh-fwd нет.

### 18.3 getCandidateAddr / p2p-channel builder (sub_18004C650)

state<10 → «get nat error, check stun server!». Body из 2276-байтной
NAT-структуры (+712, MultiStunClient) + карты интерфейсных адресов (+480) +
порта (+560), композер sub_180060420. Имя «p2p-channel», cseq из +180.

### 18.4 relay-channel builder (sub_18004AAD0)

- RandSalt/UserName при наличии ✓ (parity)
- Nonce случайный (sub_18002D630)
- **CreateDate = time64(now) − serverTimeOffset (sub_180047220)** — время
  корректируется на измеренное смещение сервера (offset обновляется из
  auth-fail «server time[%s]»). **dh-fwd шлёт чистый локальный Unix —
  источник desync-403, фикс-кандидат №1.**
- DevAuth покрывает nonce+created, ПУСТОЙ payload ✓ (parity с нашим authStr)

### 18.5 onGetAgentSucess (sub_18004D420)

- `/relay/start/`+token ✓; state 0x10
- body: **Client = «addr:port»** — **dh-fwd шлёт литерал «:0»** — расхождение
- поле «Dev» = @+672 (не выяснено)
- **интервал: `if (x) x*=2; else x=500;`** — дефолт 500 мс, удвоение, БЕЗ
  кэпа (лимит — только общий 10s-бюджет). **«1200 старт / кэп 2400» из
  старых комментариев — миф.** dh-fwd правка: initial 500ms, cap убрать.

### 18.6 CPtcpChannel::longTimeTaskDeal (sub_18003FAF0)

state==3 и тишина > **30000 мс** → heartbeat timeout → state 4. 30s
подтверждён и для UDP/PTCP пути (dh-fwd: silenceGiveUp 45s / rePunch 15s —
мягче, осознанно).

### 18.7 onBindSuccess (sub_18004DFF0) — дополнения

- peer version непуст → relay-channel, пуст → re-send p2p-channel (dh-fwd
  никогда не ре-шлёт)
- body **Type = video|audio** при media-типе ≠ default (dh-fwd не шлёт)
- 10s бюджет дословно (`+5584+10000`) ✓
- 401 на /relay/start → re-auth до 4 попыток со свежей криптой (dh-fwd
  401-ветки не имеет)

### 18.8 CPtcpChannel::connect/onConnect (sub_18003FE70 / FC00)

connect: сокет-опции → bind на общий UDP fd → phony-connect(buf+232,
port+360). onConnect: fail→state 2, успех→state 3 (таймстампы +64/+80).
Wire-уровня нет; про хрупкость SYNC-приёма — 18.2.

### 18.9 Применено (ветка `fix`, 2026-10-24)

1. **Таймеры relay-channel** (tunnel.go): старт 500 мс, чистое удвоение,
   кэп убран (relayChannelRetransInterval = 0, остался как test-only
   потолок). §18.5.
2. **401-ветка /relay/start** (relay_resilience.go): re-auth свежей
   криптой, счётчик ≤3 (§18.7), прочие ≥400 — отказ старта.
3. **SYNC TLV-парсер** (helpers.go parsePTCPSyncBody): 0=end/1=NOP/
   2=MSS-игнор/3=wscale, приём больше не байтовое сравнение (§18.2).
4. **/relay/start body**: Client = `<bindIP>:<lport>` вместо «:0» (§18.5).
5. **Ре-отправка p2p-channel** при пустой version (tunnel.go establish):
   тот же identity (CSeq replay), свежая крипта, окно channelAckWindow,
   мердж недостающих полей; non-fatal (§18.7).
6. **<Type>video|audio</Type>** — НЕ применено: DLL ставит поле только
   при сконфигурированном media-типе (v6==0 → поле отсутствует), у dh-fwd
   media-типа нет → отсутствие поля и есть DLL-паритет.

Тест TestHandshakeSmartPSSUpstreamSequence обновлён под новую
последовательность (ре-сенд после /relay/start, CSeq повторяет 6).

---

## 19. Сверка с DLL — партия 2 (2026-10-24, вечером)

### 19.1 ГЛАВНОЕ: 0x17 = PAUSE, токен-обмена не существует

P2PDll CProxyChannel::sendPause (sub_18001BE40) шлёт ровно тот кадр, который
dh-fwd считал «token auth request»: `17 00` + нули до 12 байт.
sendResume (sub_18001C3D0) = **0x19**, 16 байт, int-поле на [12:16].
Полная таблица типов из checkTouPacket (sub_18001B610), младший ниббл
body[0]: 0x10 DATA(12+BE16), 0x11 SYN(20), 0x12 ACK(16), 0x13 KA(12),
0x14 SRV(12), 0x15(20+BE16), 0x16(20), **0x17 PAUSE(12)**, 0x18(16),
**0x19 RESUME(16)**, 0x1A(16), 0x1B(12).

PAUSE/RESUME — flow control вокруг **link switch** (procLinkSwitch
sub_18001EF00): pause → миграция канала → resume → state 8, event
«link switch to p2p», код 20100. dh-fwd на relay-пути годами отправлял
пиру PAUSE и ждал несуществующий токен; errPTCPAppFallback («heartbeat
spam») был артефактом собственной ошибки.

### 19.2 processReceiver (sub_180064750)

- **Delayed ACK**: in-order → ack-тип 1 (отложенный, при флаге +256),
  out-of-order/dup → тип 2 (немедленный). dh-fwd ACKает всё немедленно
  (ackEvery=1) — кандидат на фазу 3.
- **Байтовое окно**: +64 сжимается на размер закоммиченных данных,
  восстанавливается при вычитывании; сегменты за пределами receiver
  capacity — discard («exceed receiver capacity!»). Наш вечный 0xFFFF =
  только no-scaling режим.
- OOO-буфер — сортированная карта по seq с дедупликацией (seq+len).

### 19.3 retransAckSegment (sub_180065850)

**RTO cap = 200** (`if (v12 >= 0xC8) v12 = 200`), единицы неизвестны —
нужно место записи +224 (processSender/transmit/notifyClock).
**Лимита попыток не видно** — ретрансмиссии идут, пока канал жив.
dh-fwd: floor 250ms / cap 60s / backoff 1<<retries / max 5. Сильно
расходится — ждём юниты, потом фаза 3.

### 19.4 TimeOffset (sub_180047220)

Геттер глобала dword_1801B0EBC (секунды). Писатель —
CTimeOffset::updateOffset, источник серверного времени неизвестен
(кандидат: «auth fail with server time[%s]»). Нужен псевдокод писателя.

### 19.5 sendRequest (sub_18005D980)

Обёртка: generateRequest (sub_18005D1C0 — вся сериализация, WSSE,
«SmartPSS») → пакет + порт → отправка. Нужен generateRequest.

### 19.6 Применено (ветка `fix`, партия 2)

1. **0x17-ветка relay-пути удалена** (обе копии: forced + race-горутина):
   больше не шлём PAUSE пиру и не ждём токен. forceAppRelay теперь
   ставится только детекцией версии (major ≥ 5).
2. **Мёртвый ptcpHandshake удалён** (0x19/0x1A/0x1B «token auth» —
   неверная интерпретация: 0x19 = RESUME).
3. **waitForPTCPToken + errPTCPAppFallback удалены**, ptcp_token_test.go
   удалён (тестировал несуществующий механизм).
4. **Входящие 0x17/0x19 обрабатываются**: routePTCP — PAUSE ставит
   atomic-флаг, clientReader держит локальные TCP-байты (backpressure)
   до RESUME; страховочный лимит pauseSafetyLimit=30s на случай
   потерянного RESUME. Keepalive'ы продолжают течь.
5. Таблица типов зафиксирована константами (ptcpTypePause/Resume) и в §19.1.
6. --app-relay help-текст очищен от token-мифа.

Ждёт псевдокода для фазы 3: писатель dword_1801B0EBC (updateOffset) +
его вызовы; generateRequest sub_18005D1C0; место записи RTO +224
(юниты!); processSender/transmit.

---

## 20. Сверка с DLL — партия 3 (2026-10-24, ночью)

### 20.1 CTimeOffset::updateOffset (sub_1800471A0) — источник найден

```
v1 = parseTime(Buffer)              // sub_1800460C0, strptime "%Y-%m-%dT%H:%M:%S"
if v1 != 0:
    offset = time64(NULL) - v1      // локальное «сейчас» минус серверное
    |Δoffset| > 20s → лог «change offset»
    dword_1801B0EBC = offset
```

Источник строк: **401-ответы несут ServerTime** (строка
«Response 401 with ServerTime[%s] username[%s] content[%s]»,
0x18012D300); формат — `%Y-%m-%dT%H:%M:%S` (0x180130080).
CreateDate = now − offset (см. §18.4).

### 20.2 generateRequest (sub_18005D1C0)

- путь = `"/device/" + serial + "/" + имя-запроса` (a3+8 — кластер
  p2p-channel/relay-channel/local-channel/tcprelay-channel) ✓
- **CSeq = случайный ненулевой int32 на каждый логический запрос**
  (sub_18002D630 = тот же генератор, что Nonce) — ДАЖЕ для SmartPSS.
  dh-fwd в smartpss-профиле держит счётчик (сознательный legacy-parity,
  живой easy4ip принимает) — решение о смене на random за владельцем.
- Сериализация — в sub_18002ED70 (строит в 1224-байтный структ) +
  sub_180046A90 (рендер в строку 8KB): вот где WSSE-заголовки и
  «SmartPSS». Нужны для финального паритета заголовков.

### 20.3 Применено (ветка `fix`, партия 3)

1. **serverTimeOffset** (helpers.go): atomic-глобал, паритет
   dword_1801B0EBC; updateServerTimeOffset — парсер "%Y-%m-%dT%H:%M:%S",
   локальная зона, лог при |Δ|>20s; nowAdjusted() — скорректированные
   часы.
2. **Все auth-таймстампы на nowAdjusted()**: getAuth (CreateDate),
   channelRequest.created, WSSE Created обоих профилей (createdNow).
   Skewed-часы больше не должны давать 401/403-каскады.
3. **maybeUpdateTimeOffset** (tunnel.go): ServerTime ищется в заголовке
   (case-insensitive), затем в body — подключено в четыре 401/403-пути:
   waitChannelEarlyAck (терминальные ≥400), waitRelayChannelAck (≥400),
   device-ack establish (≥400), startRelayAgent (401).
4. Тест TestUpdateServerTimeOffset (парсер, порог, nowAdjusted).

---

## 21. Сверка с DLL — партия 4 (RTO-движок + сериализатор)

### 21.1 processSender (sub_1800628E0) — ACK-обработка и RTO

**ПОДТВЕРЖДЕНО ДОСЛОВНО (наш helpers.go ARQ):**
- Jacobson: `srtt=(sample+7·srtt)>>3`, `rttvar=(3·rttvar+|Δ|)>>2`,
  первый сэмпл: srtt=sample, rttvar=sample/2
- **RTO = srtt + 4·rttvar, clamp [250, 60000] мс** (v69<=0xFA→250;
  <=0xEA60→иначе 60000) — единицы мс
- Fast retransmit на 3-м dup-ACK (счётчик +240) ✓
- Окно: `snd_wnd = u16(peer window) << wscale` — scaling подтверждён

**Нового (у dh-fwd нет):**
- Congestion control: slow start `cwnd += MSS`/ACK; CA
  `cwnd += max(MSS²/cwnd, MSS/4)`; 3-dup → `ssthresh = max(inflight,
  8·MSS)`, `cwnd = ssthresh + 8·MSS`; RTO-таймаут → `cwnd = 4·MSS`;
  dup 1..2 → `cwnd += MSS·dupcount`
- §19.3 разгадан: «cap 200» в retransAckSegment = **SACK-таймер
  min(SRTT, 200ms)** — быстрый пер-сегментный ретрансмит, отдельный
  от RTO (поэтому «без лимита попыток» — это SACK-восстановление)
- Сэмпл RTT < 20ms → >> 1 (клидж гранулярности)
- Полоса-оценщик: `(7·old + new·8бит)>>3` EWMA, окно ≥100ms

### 21.2 notifyClock (sub_180065D30) — таймеры

1. RTO-таймаут: ретрансмит старейшего; **RTO ×= 2, cap 60s**;
   state<3 (не установлен) → cap **100ms**
2. Zero-window persist: окно 0 → чистый ACK на snd_nxt−1 каждые
   (удвоенные) RTO; **тишина >15s при нулевом окне → closedown(10053)**
3. Delayed-ACK flush по дедлайну +248/+256 (значение задержки —
   где-то ставится, сайт не найден)
4. retransAckSegment — SACK-путь (21.1)

### 21.3 attemptSend/transmit (sub_180065520)

- `now - last_send > RTO → cwnd = 4·MSS` (рестарт после простоя)
- usable = min(snd_wnd, cwnd); отдаётся min(буфер, MSS) за сегмент;
  дефицит → лог «unenough space» (segmentLen/nAvailable/nUseable/
  dataLen/nInFlight/m_snd_wnd/cwnd)
- Нечего слать + есть отложенный ACK → флеш чистого ACK (delayed-ack
  из transmit), иначе ACK планируется

### 21.4 Сериализатор sub_180046A90 — ПОЛНЫЙ ПОРЯДОК ЗАГОЛОВКОВ

```
Host: …                (a1+300, presence-gated)
X-HSPV: …              (a1+364) ← НЕИЗВЕСТНЫЙ dh-fwd заголовок
Date: …                (a1+332)
X-Version: …           (a1+384)
x-pcs-request-id: …    (a1+708)
X-ToUType: …           (a1+772)
CSeq: %d               (a1[74])  ← СЕДЬМОЙ, не первый
Authorization: WSSE profile="UsernameToken"
X-WSSE: UsernameToken Username=…, PasswordDigest=…, Nonce=…, Created=…
Content-Type: %s       (реальное значение, при len>0)
Content-Length: %d     (method==0/DHPOST или len>0)
\r\n + body
```

- method-байт: 0=DHPOST 1=DHGET 2=POST 3=GET, прочее→DHGET;
  100=ответ (тогда `HTTP/1.1 %d %s` + `WWW-Authenticate: WSSE
  realm="huashi", profile="UsernameToken"` + Date-fallback)
- Порядок version→pcs-id→ToUType→CSeq→auth = наш dmss appHeaderOrder ✓;
  smartpss-legacy (CSeq первым) — рабочий отпечаток-расхождение
- sub_18002ED70 → sub_18002D740 (наполнитель полей: где WSSE-крипта
  и «SmartPSS» — следующий кандидат)

### 21.5 Решение по этой партии

Код не трогаем: ядро ARQ подтверждено (оно у нас точное), а
congestion control / SACK-таймер / delayed-ACK / zero-window-зонд —
фаза 4 (поведенческие изменения data-пути, требуют живого A/B).
Кандидаты фазы 4 по приоритету: cwnd (главный), SACK min(srtt,200ms),
delayed-ACK, X-HSPV расшифровка (кто его ставит — искать xref'ы
писателя a1+364).

---

## 22. Сверка с DLL — партия 5: диспетчеры + link switch

### 22.1 CProxyChannelClient::onTouPacket (sub_1800206A0) — ФИНАЛ ТАБЛИЦЫ ТИПОВ

| тип | имя | поведение клиента |
|---|---|---|
| 0x10 DATA, 0x12 ACK | | lookup сессии BE32@[4:8] → virtual-dispatch |
| 0x11 SYN | | «recv error msg[touTypeSyn]!» — клиент SYN не ждёт |
| 0x13 KA | | молча игнор (liveness по таймстампу) |
| 0x14 SERVICE | | **disconnect-нотифи + switch state 4** |
| 0x15 | | молча игнор |
| 0x16, 0x1B | | «invalid tou message» |
| 0x17 PAUSE | | **входящий = invalid** (шлём мы) |
| **0x18 PauseAck** | | state 3 → **значение BE32@[12:16] → +168** → state 4 |
| 0x19 RESUME | | входящий = invalid (шлём мы) |
| **0x1A ResumeAck** | | state 5 → 8 (успех); state 6 → 7 (resume-через-relay) |

Ключ: **PauseAck несёт значение устройства, которое эхом уходит в
payload RESUME** — вот смысл int@[12:16] в 0x19.

### 22.2 CTcpRelayChannel::onTouPacket (sub_180017690, путь -R)

DATA/ACK → сессионная карта (+768) → virtual-dispatch; **SYN → создание
сессии с target host:port из фрейма** (порт u16@[14], адрес — строка из
parse) — SYN у агента = команда «соединись»; KA игнор; SERVICE →
флаг готовности (+752=1); таймстамп liveness (+856).

### 22.3 Применено (ветка `fix`, партия 5)

1. **Link switch внедрён** (tryLinkSwitch): фоновая горутина после
   победы relay'я и успеха панча → PAUSE → PauseAck ≤2s (значение
   сохраняется) → SYNC на deviceRemote + flip primary → RESUME с
   эхо-значением → ResumeAck ≤2s; таймаут → повтор RESUME через
   старый relay-канал (лестница sub_18001E910). Провал = остаёмся на
   relay. Успех печатает «[+] Link switched to the direct path».
2. **routePTCP**: кейсы 0x18/0x1A → event-каналы (switchPauseAck/
   switchResumeAck), 0x14 SERVICE — лог. Комментарии 0x17/0x19
   поправлены: направление клиент→пир, входящие для DLL-клиента
   invalid (наш обработчик входящих остался как защита).
3. **Честные консольные сообщения**: «STUN punch failed! Using relay
   path» при победе relay заменено на «Using relay path (auto-upgrade
   to direct if the background punch lands)» — трёх местах (serve ×2,
   runMulti).
4. Пассивный дренаж-лог «Background STUN punch also succeeded» заменён
   на реальный tryLinkSwitch.

Открытое для живого A/B: поведение устройства на SYNC-пересинхронизации
при смене пути (наш tryLinkSwitch шлёт SYNC без confirm-бёрста — если
устройство потребует confirm, добавим из rePunch-kit).

---

## 23. Живой прогон 2026-10-24 (камера 4J065BFPAG40BE6, fw 5.2.1) — 0x16

### 23.1 Establish с фиксами: 920 мс, всё чисто

warmup→p2psrv→probe→channel→agent→start — 200 OK везде, 100 Trying
поглощён, гонка direct/relay — direct выиграл за 612 мс (устройство
само прислало cross-STUN). `Client=addr:port` принят, агент ответил
`<SID>…</SID><Time>30</Time>`. `/info/device` = 200 с ПУСТЫМ body —
fw 5.2.1 не отдаёт Info blob вообще (порт-автодетект невозможен,
дефолты 80/37777/554).

### 23.2 НОВОЕ: PTCP type 0x16 — фрейм прошивки 2024+

Устройство заливает **~1000 фреймов/сек** по 23 байта:
`16 00 1410 00000000 07 001c 0007 0014 001b 0020 010b01`
(поля: 7, 20, 28, 7, 20, 27, 32, 0x10b — похожи на версию/возможности).
DLL-2021 знает type 6 (0x16) размером 20 байт — наши 23 → даже
настоящий SmartPSS Lite отбросил бы их как error packet. Вывод:
**расширение протокола прошивок 2024+, младше нашей DLL**. Кандидат
на снятие в новом клиенте (SmartPSS 2024+ / DMSS APK) или pcap.

### 23.3 Device wedge

После ~13 минут аптайма камера перестала отвечать на BIND (0x12 CONN
не приходит вообще, 10s таймауты) — при этом p2p-channel, панч и PTCP
живы. Состояние держалось 25+ минут сквозь наши реконнекты. Вероятная
причина: зомби-realms/сессии от прогонов ДО фиксов (0x17-пауза пиру +
отсутствие 0x13 KA). Лечится ребутом камеры; RE-вопрос: есть ли в
протоколе явный клинуп realms (кандидаты: `/relay/bind/`, `/relay/begin`).

### 23.4 Realm-таймаут 30s подтверждён

Realm без трафика живёт ровно 30.0s → DVR DISC (совпадение с
`<Time>30</Time>` до миллисекунд). Порт-80 churn из §c22 — это
HTTP-конны веб-морды, закрываемые по этому бюджету + реконнекты
браузера, НЕ обязательно признак отсутствия веба. Сам вопрос «есть ли
веб-панель» остаётся открытым до чистого прогона на перезагруженной
камере: curl-проба через туннель.

