<div align="center">

<h1>dh-fwd</h1>

<p>
  <a href="./README.md">English</a> | <a href="./README_ru.md">Русский</a>
</p>

</div>

A tool for creating tunnels to Dahua cameras (by serial number) and forwarding any port to localhost via the Dahua P2P cloud protocol.

## Improvements 

- Supports **forwarding multiple ports at once**
- Supports **multithreading**
- Can build stable tunnels

### Known issues
 - Sometimes relay forwarding can work badly

> [!NOTE]
> Dahua may reject requests due to time mismatch.

## Build

Requires Go 1.26+.

```sh
git clone https://github.com/undervolter/dh-fwd
cd dh-fwd
go build -o dh-fwd .

```
## Usage

```sh
./dh-fwd <serial> [options]

```

### Flags
| Flag | Short | Description |
|---|---|---|
| --debug | -d | Verbose protocol debug output (requests, STUN packets, PTCP frames) |
| --port | -p | Port mapping (see below) |
| --threads | -mt | Number of threads (default 3) |
| --pool | - | Counter of pools |
| --smart-pss | -2 | Forwards ports 80 and 37777 at the same time |
| `--app dmss/smartpss` | `-` | Profile to choose (smartpss or dmss) |

`--help` / `-h` shows command list.
### WTF are profiles even for?
Since Dahua uses different servers depending on the ecosystem (easy4ipcloud for SmartPSS or dolynkcloud for DMSS), profile selection was added to the software.
Use the smartpss profile if you registered your camera via SmartPSS, and dmss if you registered it via DMSS. Otherwise, you'll get a 404 error from the server.
### Port Syntax (--port)
There are two ports: **local** (the one we listen on) and **remote** (the one the camera exposes).
 * **Left side:** local port
 * **Right side:** remote port
 * If only one port is specified (e.g., -p 80), remote port 80 will be opened on **any free local port**.
**Examples:**
 * -p 5080,5081,5082:80,81,82 — explicit pairs "local:remote", one-to-one
 * -p 8080,8081,8082:80 — multiple local ports to one remote port
 * -p 80-85 — port range
 * 0:81 — local port 0 means "any free port"
 * If no port is specified, default port 554 is used.
Local ports are bound to localhost.

> [!WARNING]
> If you run the software without the -p flag or specify a listening port <1024 without running the program with sudo, you may encounter the following error:
> ```sh
> Tunnel failed, reason - no listeners available for tunnel
> ```

## Modes
**Single** — forwards only 1 port:
```sh
./dh-fwd SN -p 5080:80

```
**Multi** — forwards multiple ports simultaneously. Activates automatically if multiple ports are specified, or if -mt is explicitly set:
```sh
./dh-fwd SN -p 5080,5081:80,81 -mt 4

```
```text
Opening 2 ports on SN | Threads: 3
[..] Opening SN:80 | Connecting...
[OK] Obtained SN:80 -> 127.0.0.1:5080
[OK] Obtained SN:81 -> 127.0.0.1:5081
Obtained 2 ports on SN:80,81 | localhost:5080,5081

```

## What is Dahua P2P protocol?
This is a proprietary Dahua cloud protocol used to connect to cameras via the cloud, even if the device is behind multiple NATs. The connection sequence operates as follows: the client (SmartPSS or dh-fwd) sends a request to the main server → receives an intermediate server → creates a communication channel → attempts NAT traversal → establishes a tunnel.
> [!IMPORTANT]
> Until 2025, Dahua P2P servers established tunnels without mandatory authentication. Following reported protocol vulnerabilities, devices released after late 2024 require authentication **BEFORE** establishing a tunnel. 

## Credits
Based on:
 * khoanguyen-3fc/dh-p2p — main protocol reference
 * thebadinteger/p2pwn — additional reference

**Huge thanks** to **[VGoshev](https://github.com/VGoshev)** **for his monumental contribution!** (reverse-engineered DMSS, implemented dmss profile, fixed critical bugs in Type 1 auth)

Special thanks to: **thebadinteger** and **khoanguyen-3fc**.
## ⚠️ Disclaimer
This tool was created for educational and authorized testing purposes only. Do not use it on devices you do not own or do not have explicit permission to test.
## License 
GNU General Public License v3.0 (GPLv3). See LICENSE for details.
