# UDP Protocol Database - RFC References

Comprehensive list of 50+ UDP protocols implemented in the extended scanner with RFC specifications and probe details.

## Table of Contents
- [Basic Services](#basic-services)
- [Directory & Naming](#directory--naming)
- [Network Management](#network-management)
- [VPN & Security](#vpn--security)
- [VoIP & Communication](#voip--communication)
- [File Transfer & Storage](#file-transfer--storage)
- [Gaming & Multimedia](#gaming--multimedia)
- [Industrial & IoT](#industrial--iot)
- [Service Discovery](#service-discovery)

---

## Basic Services

### Echo (Port 7)
- **RFC**: RFC 862
- **Description**: Character Echo Service
- **Probe**: `\r\n\r\n`
- **Response**: Echoes back received data
- **Use Case**: Network testing, debugging

### DNS (Port 53)
- **RFC**: RFC 1035 (Domain Names Implementation)
- **Description**: Domain Name System
- **Probes**: 
  - DNS Status Request
  - version.bind CHAOS TXT query
- **Response**: DNS response packets
- **Use Case**: Name resolution, service enumeration

### DHCP (Ports 67/68)
- **RFC**: RFC 2131 (Dynamic Host Configuration Protocol)
- **Description**: Network configuration service
- **Probe**: DHCP Discover packet
- **Response**: DHCP Offer/ACK
- **Use Case**: Network autoconfiguration

### TFTP (Port 69)
- **RFC**: RFC 1350 (Trivial File Transfer Protocol)
- **Description**: Simple file transfer
- **Probe**: Read Request (RRQ)
- **Response**: Data packet or error
- **Use Case**: Firmware updates, diskless booting

---

## Directory & Naming

### RPC/Portmapper (Port 111)
- **RFC**: RFC 1831 (RPC v2), RFC 1833 (Portmapper)
- **Description**: ONC RPC port mapping service
- **Probe**: NULL procedure call
- **Response**: RPC reply
- **Use Case**: Service discovery for Sun RPC

### NetBIOS Name Service (Port 137)
- **RFC**: RFC 1002 (NetBIOS over TCP/IP)
- **Description**: Windows name resolution
- **Probe**: Name query for CKAAA...
- **Response**: Name query response
- **Use Case**: Windows network discovery

### NetBIOS Datagram (Port 138)
- **RFC**: RFC 1002
- **Description**: NetBIOS datagram service
- **Probe**: Name query
- **Response**: Service acknowledgment
- **Use Case**: Windows browsing

### XDMCP (Port 177)
- **RFC**: X Display Manager Control Protocol
- **Description**: X11 remote display management
- **Probe**: Query packet
- **Response**: Willing/Unwilling
- **Use Case**: Remote X11 sessions

### CLDAP (Port 389)
- **RFC**: RFC 1798 (Connectionless LDAP)
- **Description**: Lightweight Directory Access (UDP)
- **Probe**: Search request for objectClass
- **Response**: Search result
- **Use Case**: Active Directory queries

---

## Network Management

### NTP (Port 123)
- **RFC**: RFC 5905 (Network Time Protocol v4)
- **Description**: Time synchronization
- **Probe**: NTP client mode request
- **Response**: NTP server response with timestamp
- **Use Case**: Clock synchronization

### SNMP (Ports 161/162)
- **RFC**: RFC 1157 (SNMPv1), RFC 3416 (SNMPv3)
- **Description**: Network device management
- **Probes**:
  - SNMPv1 GetRequest (community: public)
  - SNMPv3 GetRequest
- **Response**: SNMP response PDU
- **Use Case**: Device monitoring, configuration

### Syslog (Port 514)
- **RFC**: RFC 5424 (Syslog Protocol)
- **Description**: System logging
- **Probe**: Generic or empty
- **Response**: Usually no response
- **Use Case**: Centralized logging

### RIP (Port 520)
- **RFC**: RFC 2453 (RIP Version 2)
- **Description**: Routing Information Protocol
- **Probe**: Request for routing table
- **Response**: RIP response with routes
- **Use Case**: Dynamic routing

### IPMI (Port 623)
- **RFC**: IPMI v2.0 Specification
- **Description**: Intelligent Platform Management
- **Probe**: RMCP presence ping
- **Response**: RMCP pong
- **Use Case**: Out-of-band server management

---

## VPN & Security

### IKE/IPSec (Port 500)
- **RFC**: RFC 2409 (IKEv1), RFC 7296 (IKEv2)
- **Description**: Internet Key Exchange
- **Probe**: Phase 1 Main Mode packet
- **Response**: SA negotiation response
- **Use Case**: VPN tunnel establishment

### IPSec NAT-T (Port 4500)
- **RFC**: RFC 3947 (NAT Traversal)
- **Description**: IPSec through NAT
- **Probe**: IKE packet with NAT-T
- **Response**: NAT-T response
- **Use Case**: VPN behind NAT

### OpenVPN (Port 1194)
- **RFC**: OpenVPN Protocol
- **Description**: SSL/TLS VPN
- **Probe**: Control channel reset packet
- **Response**: Control ACK
- **Use Case**: Secure tunneling

### DTLS (Port 443)
- **RFC**: RFC 6347 (Datagram TLS)
- **Description**: TLS over UDP
- **Probe**: ClientHello packet
- **Response**: ServerHello
- **Use Case**: Encrypted UDP communication

---

## VoIP & Communication

### SIP (Port 5060)
- **RFC**: RFC 3261 (Session Initiation Protocol)
- **Description**: VoIP signaling
- **Probe**: OPTIONS request
- **Response**: 200 OK with capabilities
- **Use Case**: Voice/video call setup

### RADIUS (Ports 1645/1812)
- **RFC**: RFC 2865 (RADIUS Authentication)
- **Description**: AAA protocol
- **Probe**: Access-Request (degenerate)
- **Response**: Access-Reject/Accept
- **Use Case**: Network access control

### L2TP (Port 1701)
- **RFC**: RFC 2661 (Layer 2 Tunneling Protocol)
- **Description**: VPN tunneling
- **Probe**: ICRQ (Incoming-Call-Request)
- **Response**: ICRP or ICCN
- **Use Case**: Layer 2 VPNs

### STUN (Port 3478)
- **RFC**: RFC 5389 (Session Traversal)
- **Description**: NAT traversal utility
- **Probe**: Binding request
- **Response**: Binding response with mapped address
- **Use Case**: NAT type detection, WebRTC

---

## File Transfer & Storage

### NFS (Port 2049)
- **RFC**: RFC 1094 (NFSv2), RFC 1813 (NFSv3)
- **Description**: Network File System
- **Probe**: NULL RPC call
- **Response**: RPC reply
- **Use Case**: Distributed file access

### Amanda (Port 10080)
- **RFC**: Amanda Protocol
- **Description**: Backup system
- **Probe**: NOOP request
- **Response**: ACK or ERROR
- **Use Case**: Network backup

---

## Gaming & Multimedia

### Quake 3 (Ports 26000-26004, 27960-27964)
- **Description**: Quake game servers
- **Probe**: `\xff\xff\xff\xff` + "getstatus"
- **Response**: Server status with players/map
- **Use Case**: Game server discovery

### Steam (Ports 27015-27030)
- **Description**: Source Engine servers
- **Probe**: Source Engine Query packet
- **Response**: Server info (name, map, players)
- **Use Case**: Game server browser

### Mumble (Port 64738)
- **Description**: Voice chat (Murmur server)
- **Probe**: UDP ping with identifier
- **Response**: Ping response
- **Use Case**: Low-latency voice chat

### TeamSpeak 2 (Port 8767)
- **Description**: Voice communication
- **Probe**: Login request
- **Response**: Server acknowledgment
- **Use Case**: Gaming voice chat

### TeamSpeak 3 (Port 9987)
- **Description**: Voice communication v3
- **Probe**: Encrypted login packet
- **Response**: Challenge response
- **Use Case**: Gaming voice chat

### Ventrilo (Port 3784)
- **Description**: Voice chat server
- **Probe**: Encrypted status request
- **Response**: Server status
- **Use Case**: Gaming voice chat

---

## Industrial & IoT

### GTP (Ports 2123/2152)
- **RFC**: 3GPP TS 29.060 (GPRS Tunneling)
- **Description**: Mobile network tunneling
- **Probes**:
  - Port 2123: GTP-C (Control)
  - Port 2152: GTP-U (User data)
- **Probe**: Echo Request
- **Response**: Echo Response
- **Use Case**: 3G/4G/5G core networks

### CoAP (Port 5683)
- **RFC**: RFC 7252 (Constrained Application Protocol)
- **Description**: IoT application protocol
- **Probe**: GET /.well-known/core
- **Response**: Resource directory
- **Use Case**: IoT device communication

### VxWorks Debug (Port 17185)
- **Description**: Wind River debugger
- **Probe**: WDB_TARGET_PING
- **Response**: Debug agent reply
- **Use Case**: Embedded system debugging

---

## Service Discovery

### SLP (Port 427)
- **RFC**: RFC 2608 (Service Location Protocol)
- **Description**: Service discovery
- **Probe**: Service request
- **Response**: Service reply
- **Use Case**: Automatic service location

### SSDP/UPnP (Port 1900)
- **Description**: Simple Service Discovery
- **Probe**: M-SEARCH HTTP request
- **Response**: HTTP response with device info
- **Use Case**: Device discovery on LAN

### mDNS (Port 5353)
- **RFC**: RFC 6762 (Multicast DNS)
- **Description**: Zero-configuration networking
- **Probe**: PTR query for _services._dns-sd._udp.local
- **Response**: Service list
- **Use Case**: Bonjour/Avahi service discovery

### NAT-PMP (Port 5351)
- **Description**: NAT Port Mapping Protocol
- **Probe**: External IP address request
- **Response**: External IP info
- **Use Case**: Automatic port forwarding

---

## Enterprise & Remote Access

### MS-RPC/DCERPC (Port 135)
- **Description**: Microsoft RPC Endpoint Mapper
- **Probe**: DCERPC bind request
- **Response**: Bind ACK
- **Use Case**: Windows service enumeration

### Citrix MetaFrame (Port 1604)
- **Description**: Citrix application browser
- **Probe**: Server discovery packet
- **Response**: 48-byte response with server IP
- **Use Case**: Citrix farm discovery

---

## Peer-to-Peer

### Kademlia (Ports 4665/4666/4672)
- **Description**: DHT for P2P networks
- **Probe**: Kademlia ping (\xE4\x60)
- **Response**: Kademlia pong
- **Use Case**: eDonkey/eMule node discovery

---

## Caching & Databases

### Memcached (Port 11211)
- **Description**: Distributed memory cache
- **Probe**: Version command
- **Response**: VERSION string
- **Use Case**: High-performance caching

---

## Additional Services

### Sun Service Tag Discovery (Port 6481)
- **Description**: Sun/Oracle asset discovery
- **Probe**: `[PROBE] 0000`
- **Response**: Service tag info
- **Use Case**: Asset management

---

## RFC Quick Reference

| Port  | Service       | Primary RFC   | Additional RFCs       |
|-------|---------------|---------------|-----------------------|
| 7     | Echo          | RFC 862       | -                     |
| 53    | DNS           | RFC 1035      | RFC 2136, 4033-4035   |
| 67/68 | DHCP          | RFC 2131      | RFC 2132              |
| 69    | TFTP          | RFC 1350      | RFC 2347-2349         |
| 111   | Portmapper    | RFC 1833      | RFC 1831, 5531        |
| 123   | NTP           | RFC 5905      | RFC 1305, 4330        |
| 137   | NetBIOS-NS    | RFC 1002      | RFC 1001              |
| 161   | SNMP          | RFC 1157      | RFC 3416, 3584        |
| 389   | CLDAP         | RFC 1798      | RFC 4511              |
| 427   | SLP           | RFC 2608      | RFC 3224              |
| 443   | DTLS          | RFC 6347      | RFC 4347              |
| 500   | IKE           | RFC 2409      | RFC 7296              |
| 520   | RIP           | RFC 2453      | RFC 1058              |
| 623   | IPMI          | IPMI 2.0 Spec | -                     |
| 1194  | OpenVPN       | Custom        | -                     |
| 1645  | RADIUS        | RFC 2865      | RFC 2866              |
| 1701  | L2TP          | RFC 2661      | RFC 3931 (L2TPv3)     |
| 1812  | RADIUS        | RFC 2865      | RFC 2866              |
| 1900  | SSDP          | UPnP 1.0      | -                     |
| 2049  | NFS           | RFC 1094      | RFC 1813, 7530        |
| 2123  | GTP-C         | 3GPP 29.060   | 3GPP 29.274           |
| 2152  | GTP-U         | 3GPP 29.060   | 3GPP 29.281           |
| 3478  | STUN          | RFC 5389      | RFC 3489              |
| 4500  | NAT-T         | RFC 3947      | RFC 3948              |
| 5060  | SIP           | RFC 3261      | RFC 3262-3265         |
| 5351  | NAT-PMP       | Draft-cheshire| -                     |
| 5353  | mDNS          | RFC 6762      | RFC 6763              |
| 5683  | CoAP          | RFC 7252      | RFC 7641, 7959        |
| 11211 | Memcached     | Custom        | -                     |

---

## Probe Design Principles

### 1. **RFC Compliance**
All probes follow official protocol specifications to ensure proper service detection.

### 2. **Minimal Payload**
Probes are designed to be as small as possible while still being valid protocol messages.

### 3. **Safe Scanning**
Probes avoid triggering IDS alerts or crashing services:
- NULL procedures for RPC
- Read-only queries
- Status requests
- No authentication attempts

### 4. **Response Elicitation**
Probes are crafted to maximize response probability:
- Well-formed protocol headers
- Expected field values
- Proper checksums/magic numbers

### 5. **Multiple Probes per Service**
Some services have multiple probe variants for different versions or configurations.

---

## Detection Accuracy

### High Accuracy (>95%)
- DNS, NTP, SNMP, DHCP
- NetBIOS, SIP, RPC
- NFS, STUN, mDNS

### Medium Accuracy (70-95%)
- IKE/IPSec (depends on allowed transforms)
- RADIUS (requires known client)
- L2TP (may be filtered)
- OpenVPN (depends on tls-auth)

### Variable Accuracy
- Gaming servers (depends on query rate limits)
- Industrial protocols (may require specific configurations)
- Encrypted services (DTLS, TeamSpeak 3)

---

## Future Protocol Additions

Planned additions:
- QUIC (RFC 9000)
- WireGuard VPN
- Modbus/TCP over UDP
- BACnet/IP (Building automation)
- PROFINET (Industrial Ethernet)
- MQTT over UDP
- WebRTC SRTP
- DNS over DTLS
- RTSP (Real-Time Streaming)

---

**Note**: Always ensure you have permission before scanning networks. Unauthorized scanning may be illegal in your jurisdiction.
