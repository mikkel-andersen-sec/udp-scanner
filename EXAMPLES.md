# UDP Scanner Usage Examples

## Basic Scanning

### Single Port Scan
```bash
# Test if DNS is running
sudo ./udp_scanner 8.8.8.8 53 53
```

### Port Range Scan
```bash
# Scan common UDP ports
sudo ./udp_scanner 192.168.1.1 1 1000
```

### Full UDP Port Scan
```bash
# Scan all 65535 ports (very slow)
sudo ./udp_scanner 10.0.0.1 1 65535
```

---

## Service-Specific Scans

### DNS Servers
```bash
# Google DNS
sudo ./udp_scanner 8.8.8.8 53 53

# Cloudflare DNS
sudo ./udp_scanner 1.1.1.1 53 53

# Local DNS
sudo ./udp_scanner 192.168.1.1 53 53
```

### NTP Servers
```bash
# Google NTP
sudo ./udp_scanner time.google.com 123 123

# Pool.ntp.org
sudo ./udp_scanner pool.ntp.org 123 123
```

### SNMP Devices
```bash
# Network equipment
sudo ./udp_scanner 192.168.1.1 161 161

# SNMP trap receiver
sudo ./udp_scanner 192.168.1.10 162 162
```

### VPN Services
```bash
# IKE/IPSec
sudo ./udp_scanner vpn.example.com 500 500

# OpenVPN
sudo ./udp_scanner vpn.example.com 1194 1194

# L2TP
sudo ./udp_scanner vpn.example.com 1701 1701
```

### VoIP Services
```bash
# SIP server
sudo ./udp_scanner voip.example.com 5060 5060

# STUN server
sudo ./udp_scanner stun.l.google.com 3478 3478
```

---

## Network Discovery

### Local Network Scan
```bash
# Scan router
sudo ./udp_scanner 192.168.1.1 1 1000

# Scan specific host
sudo ./udp_scanner 192.168.1.100 1 1000
```

### Common Services Scan
```bash
# DNS, DHCP, TFTP, NTP, SNMP
sudo ./udp_scanner 192.168.1.1 53 53
sudo ./udp_scanner 192.168.1.1 67 68
sudo ./udp_scanner 192.168.1.1 69 69
sudo ./udp_scanner 192.168.1.1 123 123
sudo ./udp_scanner 192.168.1.1 161 161
```

---

## Extended Scanner Examples

### Using Extended Version
```bash
# Build extended scanner
gcc -O2 -o udp_scanner_extended udp_scanner_extended.c

# Scan with 50+ protocol probes
sudo ./udp_scanner_extended 192.168.1.1 1 2000
```

### Gaming Server Discovery
```bash
# Quake 3
sudo ./udp_scanner_extended game.server.com 27960 27964

# Steam/Source
sudo ./udp_scanner_extended game.server.com 27015 27030

# Mumble
sudo ./udp_scanner_extended voice.server.com 64738 64738
```

### Industrial Protocols
```bash
# IPMI
sudo ./udp_scanner_extended 192.168.1.50 623 623

# GTP (mobile core)
sudo ./udp_scanner_extended 10.0.0.1 2123 2123
sudo ./udp_scanner_extended 10.0.0.1 2152 2152
```

---

## Advanced Techniques

### Scan Behind NAT
```bash
# Scan public IP from inside network
sudo ./udp_scanner <your-public-ip> 1 1000
```

### Service Version Detection
```bash
# Extended scanner shows protocol responses
sudo ./udp_scanner_extended 192.168.1.1 53 53 | grep bytes
```

### Multiple Target Scanning
```bash
# Bash loop for multiple hosts
for ip in 192.168.1.{1..254}; do
    echo "Scanning $ip"
    sudo ./udp_scanner $ip 53 53
done
```

---

## Output Analysis

### Understanding Output

```
[OPEN] Port 53/udp DNS (RFC 1035) - 87 bytes
```
- **Status**: OPEN
- **Port**: 53
- **Protocol**: UDP
- **Service**: DNS
- **RFC**: 1035
- **Response**: 87 bytes received

```
[CLOSED] Port 54/udp
```
- **Status**: CLOSED
- Port sent ICMP Port Unreachable

```
[OPEN|FILTERED] Port 161/udp SNMP (RFC 1157)
```
- **Status**: OPEN or FILTERED
- No response (timeout)
- Could be open but not responding
- Could be filtered by firewall

```
[FILTERED] Port 137/udp (ICMP code 1)
```
- **Status**: FILTERED
- ICMP Host Unreachable (code 1)
- Firewall is blocking

---

## Practical Scenarios

### 1. Home Network Audit
```bash
# Check router services
sudo ./udp_scanner 192.168.1.1 1 1000

# Look for:
# - Port 53: DNS server
# - Port 67: DHCP server
# - Port 123: NTP server
# - Port 161: SNMP (security risk if public)
# - Port 1900: UPnP (potential security issue)
```

### 2. VPN Connectivity Test
```bash
# Test if VPN endpoint is reachable
sudo ./udp_scanner vpn.company.com 500 500   # IKE
sudo ./udp_scanner vpn.company.com 1194 1194 # OpenVPN
sudo ./udp_scanner vpn.company.com 1701 1701 # L2TP
```

### 3. VoIP Troubleshooting
```bash
# Test SIP server
sudo ./udp_scanner sip.provider.com 5060 5060

# Test STUN for NAT traversal
sudo ./udp_scanner stun.server.com 3478 3478
```

### 4. Network Infrastructure Mapping
```bash
# DNS servers
sudo ./udp_scanner 8.8.8.8 53 53
sudo ./udp_scanner 1.1.1.1 53 53

# NTP servers
sudo ./udp_scanner time1.google.com 123 123
sudo ./udp_scanner time2.google.com 123 123

# Network equipment
sudo ./udp_scanner 192.168.1.1 161 161  # SNMP
sudo ./udp_scanner 192.168.1.1 520 520  # RIP
```

### 5. Security Assessment
```bash
# Common vulnerable services
sudo ./udp_scanner target.com 53 53    # DNS amplification?
sudo ./udp_scanner target.com 123 123  # NTP amplification?
sudo ./udp_scanner target.com 161 161  # SNMP with default community?
sudo ./udp_scanner target.com 1900 1900 # UPnP exposed?
```

---

## Performance Tips

### Speed vs Accuracy
```bash
# Faster (less reliable)
# Reduce timeout in source: TIMEOUT_SEC 1
# Reduce retries: MAX_RETRIES 1

# Slower (more reliable)
# Increase timeout: TIMEOUT_SEC 5
# Increase retries: MAX_RETRIES 3
```

### Rate Limiting
```c
// Modify delay in main():
usleep(10000);  // 10ms (default, ~100 packets/sec)
usleep(50000);  // 50ms (slower, stealthier)
usleep(1000);   // 1ms (faster, more aggressive)
```

---

## Combining with Other Tools

### With Nmap
```bash
# First: Quick UDP scan with this tool
sudo ./udp_scanner 192.168.1.1 1 1000

# Then: Detailed scan of open ports with Nmap
sudo nmap -sU -sV -p 53,123,161 192.168.1.1
```

### With Wireshark
```bash
# Terminal 1: Start Wireshark capture
sudo wireshark -i eth0 -k -f "udp"

# Terminal 2: Run scanner
sudo ./udp_scanner 192.168.1.1 53 53
```

### Output to File
```bash
# Save results
sudo ./udp_scanner 192.168.1.1 1 1000 > scan_results.txt

# Save with timestamp
sudo ./udp_scanner 192.168.1.1 1 1000 | tee scan_$(date +%Y%m%d_%H%M%S).txt
```

---

## Scripting Examples

### Scan Multiple Hosts
```bash
#!/bin/bash
HOSTS="192.168.1.1 192.168.1.100 192.168.1.254"
PORTS="53 123 161"

for host in $HOSTS; do
    echo "\n=== Scanning $host ==="
    for port in $PORTS; do
        sudo ./udp_scanner $host $port $port
    done
done
```

### Automated Network Survey
```bash
#!/bin/bash
# Scan entire subnet for common UDP services
SUBNET="192.168.1"
COMMON_PORTS="53,67,69,123,161,500,1194,5060"

for i in {1..254}; do
    IP="$SUBNET.$i"
    echo "Scanning $IP..."
    sudo ./udp_scanner $IP 1 1000 | grep OPEN
done
```

---

## Troubleshooting

### No Response from Known Service
```bash
# Possible causes:
# 1. Firewall blocking
# 2. Service configured not to respond to probes
# 3. Rate limiting
# 4. Service requires authentication

# Try increasing timeout and retries
```

### False Positives
```bash
# Reduce false positives:
# - Use protocol-specific probes (extended scanner)
# - Increase retry count
# - Verify with Nmap: sudo nmap -sU -sV -p <port> <target>
```

### Slow Scanning
```bash
# UDP scanning is inherently slow due to:
# - No connection handshake
# - ICMP rate limiting
# - Timeouts for no response

# Typical speeds:
# - With responses: 50-100 ports/sec
# - Without responses: 1-5 ports/sec (due to timeouts)
```

---

**Security Reminder**: Always obtain permission before scanning networks you don't own!
