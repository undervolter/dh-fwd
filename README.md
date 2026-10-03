<div align="center">

<h1>dh-fwd</h1>

<p>
  <a href="./README.md">English</a> | <a href="./README_ru.md">Русский</a>
</p>

</div>
<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/github/v/release/undervolter/dh-fwd?style=flat-square&color=blue" alt="Release">
  <img src="https://img.shields.io/github/license/undervolter/dh-fwd?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/downloads/undervolter/dh-fwd/total?style=flat-square&color=blue" alt="Downloads">
</p>

Software for creating tunnels to a Dahua camera (by serial number), forwarding any port to localhost via the Dahua cloud protocol.

## Features

- Supports **forwarding multiple ports at once**
- Supports connecting to cameras **released after 2024**
- Supports multithreading
- Builds stable tunnels to the camera
- Auto-updater

> [!CAUTION]
> Before **2024**, Dahua's P2P servers established connections *without authentication*. After all the fuss over the protocol's vulnerability, devices released after 2024.07 now require authentication.

> [!NOTE]
> Also, Dahua may reject requests if you have a time desync.

> [!IMPORTANT]
> The tunnel won't build if you're using VPN or proxy!
> If the connection to the camera goes through an intermediate server, the web panel might not work! Unfortunately, this is specifically a problem on Dahua's server side, so there's nothing to be done about it.

## Build

```sh
git clone https://github.com/undervolter/dh-fwd
cd dh-fwd
go build .

```

**Usage:**

```sh
./dh-fwd <serial> [options]

```

### Flags

| Flag | Short | Description |
| --- | --- | --- |
| `--port` | `-p` | Port mapping (e.g. `5080:80`, `554`, see below) |
| `--creds` | `-c` | Credentials `username:password` (Type 1 Auth, auto-salt) |
| `--type` | `-t` | Device auth type: `0` = no auth (default), `1` = with auth |
| `--username` | `-u` | Username |
| `--password` | `-P` | Password |
| `--app <smartpss\|dmss>` | `-` | Profile selection |
| `--app-relay` | `-ar` | Force app relay dialect |
| `--tcp-relay` | `-R` | Force switch to TCP relay |
| `--smartpss`, `--smart-pss` | `-2` | Forwards 80 and 37777 on free local ports |
| `--threads` | `-mt` | Number of parallel tunnels (default 3) |
| `--pool`, `--pools` | `-` | Number of realms in the pool (default 50; 0 disables) |
| `--info` | `-` | Query `/info/device/<SN>` and decrypt the Info blob (randsalt, devP2PVersion) |
| `--heartbeat-timeout` | `-hb` | PTCP heartbeat timeout (default 10s) |
| `--debug` | `-d` | Debug (logs are in dh-fwd.log) |
| `--log-retries` | `-lr` | Log retry attempts with timestamps |

`--help` / `-h` prints a list of all available commands.

### What are profiles even for?
Since Dahua uses different servers (easy4ipcloud for smartpss, dolynkcloud for dmss), profile selection was added to the software.
Use the smartpss profile if you registered your camera through SmartPSS, and dmss if you registered it through DMSS. Otherwise you'll get a 404 from one of the servers.

### Port Syntax (`--port`)

There are 2 kinds of ports: local (the one we listen on) and remote (the port on the camera itself).

Format: `local:remote`.

If only one port is given (e.g. `-p 80`), remote port 80 is opened on **any** free local port.

Input examples:

* `-p 5080,5081,5082:80,81,82`
* `-p 8080,8081,8082:80`
* `-p 80-85`
* `-p 81` (forwards camera port 81 to ANY port on the system);
* if no port is given at all — port 554 is opened by default.

Local ports are bound to `127.0.0.1` (`localhost`).

> [!WARNING]
> If you run the software without the -p flag, or bind ports `<1024` without superuser privileges (`sudo` / administrator), you'll get this error:
> ```sh
> Tunnel failed, reason - no listeners available for tunnel
> 
> ```

### Modes

**Single** — forwards only 1 port:

```sh
./dh-fwd SN -p 1337:80
```
```text
[23:54] dh-fwd v2.4.1 (latest)
Connecting to 4C04441PAG726F6:80 [=======================>] 100 % | Listening on :1337
```

**Multi** — forwards several ports at once. Kicks in automatically if multiple ports are given, or if multithreaded mode is enabled:

```sh
./dh-fwd SN -p 5080,5081:80,81 -mt 4

```

```text
[23:59] dh-fwd v2.4.1 (latest)
Connecting to 4C04441PAG726F6:80,81 [=======================>] 100 % | Listening on :5080, 5081
```

## What is Dahua P2P?

This is Dahua's proprietary cloud protocol, used to connect to devices over the internet even when the camera is behind multiple layers of NAT.

Work pipeline:

1. The client (SmartPSS or `dh-fwd`) sends a request to the master authorization server
2. Receives the address of an intermediate server
3. Initiates a communication channel and runs NAT traversal (STUN/ICE)
4. PROFIT

## Credits

Based on and inspired by:

* khoanguyen-3fc/dh-p2p — base implementation of the Dahua P2P protocol
* [thebadinteger/p2pwn](https://github.com/thebadinteger/p2pwn/tree/main/core/p2p) — groundwork on the networking side

**Huge thanks to** **[VGoshev](https://github.com/VGoshev)** **for his monumental work!** *(added the dmss profile, fixed critical authentication bugs, reverse-engineered DMSS, and did a ton of testing)*

Many thanks to the authors: **thebadinteger** and **khoanguyen-3fc**.

### ⚠️ Disclaimer

**This utility was created solely for educational and research purposes. Do not use it to gain unauthorized access to devices that aren't yours.**

## License

Distributed under the MIT license; see the `LICENSE` file for details.
