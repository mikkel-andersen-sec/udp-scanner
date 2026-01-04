# Professional UDP Port Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Language: C](https://img.shields.io/badge/Language-C-blue.svg)](https://en.wikipedia.org/wiki/C_(programming_language))

A professional UDP port scanner written in C with RFC-compliant protocol-specific probes for accurate service detection.

## Why UDP Scanning is Hard

UDP is a **connectionless protocol** - unlike TCP, UDP services don't respond with acknowledgments. This makes UDP scanning challenging:

1. **No handshake**: UDP has no SYN/ACK mechanism
2. **Silent open ports**: Most open UDP ports don't respond to generic probes
3. **ICMP rate limiting**: Targets often rate-limit ICMP Port Unreachable messages
4. **Firewall filtering**: Many firewalls drop UDP packets silently

## Solution: Protocol-Specific Probes

This scanner implements **RFC-compliant protocol-specific payloads** for common UDP services. By sending valid protocol data, we can elicit responses from services that would otherwise remain silent.

### Supported Protocols

| Port | Service | RFC | Probe Type |
|------|---------|-----|------------|
| 53 | DNS | RFC 1035 | DNS query (version.bind) |
| 123 | NTP | RFC 5905 | NTP client request |
| 161 | SNMP | RFC 1157 | SNMPv1 GetRequest |
| 67/68 | DHCP | RFC 2131 | DHCP Discover |
| 137/138 | NetBIOS | RFC 1002 | NetBIOS Name Query |
| 5060 | SIP | RFC 3261 | SIP OPTIONS request |
| 69 | TFTP | RFC 1350 | Generic probe |
| 514 | Syslog | RFC 5424 | Generic probe |
| 520 | RIP | RFC 2453 | Generic probe |
| 1900 | SSDP/UPnP | - | Generic probe |

## Features

✅ **Protocol-Specific Probes** - RFC-compliant payloads for accurate detection  
✅ **ICMP Detection** - Captures ICMP Port Unreachable messages  
✅ **Service Fingerprinting** - Identifies services by response analysis  
✅ **Rate Limiting** - Prevents network flooding  
✅ **Retry Logic** - Handles packet loss  
✅ **Statistics** - Detailed scan metrics  
✅ **Low-level Sockets** - Direct control over UDP/ICMP  

## Technical Approach

### Detection Methods

1. **UDP Response Detection**
   - Service responds to protocol-specific probe
   - **Result**: Port is OPEN

2. **ICMP Port Unreachable**
   - Target sends ICMP Type 3, Code 3
   - **Result**: Port is CLOSED

3. **No Response (Timeout)**
   - No UDP response, no ICMP message
   - **Result**: Port is OPEN|FILTERED

4. **ICMP Filtering**
   - ICMP Type 3, Code 1/2/9/10/13
   - **Result**: Port is FILTERED

### Why C?

C is the optimal language for UDP scanning:

- **Raw sockets**: Direct access to ICMP
- **Performance**: Minimal overhead for network I/O
- **Control**: Precise timing and socket options
- **System calls**: Direct `sendto()`, `recvfrom()`, `select()`
- **Portability**: Works on Linux, BSD, macOS

## Installation

### Prerequisites

- GCC compiler
- Linux/Unix system
- Root privileges (for ICMP socket)

### Build

```bash
git clone https://github.com/mikkel-andersen-sec/udp-scanner.git
cd udp-scanner
make
```

### Install System-Wide (Optional)

```bash
sudo make install
```

## Usage

### Basic Syntax

```bash
sudo ./udp_scanner <target_ip> <start_port> <end_port>
```

### Examples

**Scan common UDP ports:**
```bash
sudo ./udp_scanner 192.168.1.1 53 53
```

**Scan UDP port range:**
```bash
sudo ./udp_scanner 10.0.0.1 1 1000
```

**Scan all UDP ports:**
```bash
sudo ./udp_scanner 192.168.1.1 1 65535
```

**Scan specific services:**
```bash
# DNS
sudo ./udp_scanner 8.8.8.8 53 53

# NTP
sudo ./udp_scanner time.google.com 123 123

# SNMP
sudo ./udp_scanner 192.168.1.1 161 161

# DHCP
sudo ./udp_scanner 192.168.1.1 67 68
```

## Output Interpretation

```
[OPEN] Port 53/udp DNS (service responded: 45 bytes)
```
✅ Service is running and responded to probe

```
[CLOSED] Port 54/udp (ICMP port unreachable)
```
🚫 Port is closed (confirmed via ICMP)

```
[OPEN|FILTERED] Port 161/udp SNMP (no response)
```
❓ Port may be open but didn't respond, or filtered by firewall

```
[FILTERED] Port 137/udp (ICMP unreachable type 3, code 1)
```
🛡️ Firewall is blocking access

## Sample Output

```
$ sudo ./udp_scanner 192.168.1.1 53 161
Starting UDP scan on 192.168.1.1
Scanning ports 53-161
Using protocol-specific probes for service detection

[OPEN] Port 53/udp DNS (service responded: 87 bytes)
[CLOSED] Port 54/udp (ICMP port unreachable)
[CLOSED] Port 55/udp (ICMP port unreachable)
[OPEN|FILTERED] Port 123/udp NTP (no response)
[OPEN] Port 161/udp SNMP (service responded: 134 bytes)

=== Scan Statistics ===
Total ports scanned: 109
Open ports: 2
Closed ports: 105
Filtered/Open|Filtered: 2
Scan duration: 21.45 seconds
Scan rate: 5.08 ports/sec
```

## Security Considerations

⚠️ **Legal Notice**: Only scan systems you own or have explicit permission to test.

### Ethical Use

- Always obtain written authorization
- Respect rate limits and network policies
- Don't scan production systems without approval
- Be aware of local computer crime laws

### Detection Risk

UDP scanning can be detected by:
- Intrusion Detection Systems (IDS)
- Firewall logs
- Network monitoring tools

## Performance Tuning

### Scan Speed

Modify the delay in `main()`:
```c
usleep(10000); // 10ms delay (default)
usleep(1000);  // 1ms delay (faster, more aggressive)
usleep(50000); // 50ms delay (slower, stealthier)
```

### Timeout Settings

Adjust timeout in source:
```c
#define TIMEOUT_SEC 2  // 2 seconds (default)
#define TIMEOUT_SEC 5  // 5 seconds (slower networks)
```

### Retries

```c
#define MAX_RETRIES 2  // 2 retries (default)
#define MAX_RETRIES 3  // More reliable, slower
```

## Limitations

1. **ICMP Rate Limiting**: Most systems rate-limit ICMP responses (Linux default: 1/second)
2. **Firewall Evasion**: Cannot detect ports behind stateful firewalls that drop packets silently
3. **Root Required**: Needs root for raw ICMP socket
4. **Single-threaded**: Currently scans one port at a time (multithreading planned)
5. **IPv4 Only**: No IPv6 support yet

## Roadmap

- [ ] Multi-threading support
- [ ] IPv6 support
- [ ] More protocol probes (RADIUS, ISAKMP, etc.)
- [ ] Stealth mode (timing randomization)
- [ ] Output formats (JSON, XML, CSV)
- [ ] Integration with Nmap service database
- [ ] Packet fragmentation detection
- [ ] Banner grabbing

## Technical References

### RFCs Implemented

- **RFC 768** - User Datagram Protocol (UDP)
- **RFC 792** - Internet Control Message Protocol (ICMP)
- **RFC 1035** - Domain Names (DNS)
- **RFC 1002** - NetBIOS Name Service
- **RFC 1157** - Simple Network Management Protocol (SNMP)
- **RFC 2131** - Dynamic Host Configuration Protocol (DHCP)
- **RFC 3261** - Session Initiation Protocol (SIP)
- **RFC 5905** - Network Time Protocol (NTP)

### Additional Reading

- [Nmap UDP Scanning Techniques](https://nmap.org/book/scan-methods-udp-scan.html)
- [UDP Scan with ICMP Port Unreachable](https://blog.stalkr.net/2010/05/udp-scan-with-icmp-port-unreachable-and.html)
- [RFC 9868 - UDP Options](https://datatracker.ietf.org/doc/rfc9868/)

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your protocol probe or enhancement
4. Test thoroughly
5. Submit a pull request

## License

MIT License - See [LICENSE](LICENSE) file

## Author

**Mikkel Andersen**  
Senior Web Application Penetration Tester | OSCP  
[LinkedIn](https://www.linkedin.com/in/mikkel-andersen-5a9a32185/)

## Disclaimer

This tool is for educational and authorized security testing purposes only. Unauthorized port scanning may be illegal in your jurisdiction. The author assumes no liability for misuse of this software.

---

**Built with ❤️ and low-level C sockets**
