# PCredz

This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

## Features

- Extract from a pcap file or from a live interface IPv4 and IPv6:
  - Credit card numbers
  - POP
  - SMTP
  - IMAP
  - SNMP community string
  - FTP
  - HTTP (NTLM/Basic/HTTP Forms)
  - NTLMv1/v2 (DCE-RPC,SMBv1/2,LDAP, MSSQL, HTTP, etc)
  - Kerberos (AS-REQ Pre-Auth etype 23) hashes.

- All hashes are displayed in a hashcat format (use -m 7500 for kerberos, -m 5500 for NTLMv1, -m 5600 for NTLMv2).
- Log all credentials and information to a file (CredentialDump-Session.log).
- Log credentials in the logs/ folder. MSKerb.txt, NTLMv1.txt and NTLMv2.txt can be directly fed to hashcat. 

## Install

### Docker
Install docker and clone the repo

Build the container
```bash
$ docker build . -t pcredz
```

Then use the command below to map the current working directory inside the Pcredz container. This is useful for moving .pcap files to parse or for retrieving log files from a live capture.
```bash
$ docker run --net=host -v $(pwd):/opt/Pcredz -it pcredz
```

### Linux

On a debian based OS bash:

```bash
pip install pcapy-ng requests
```

Or with apt (Debian/Ubuntu/Kali):
```
sudo apt install python3-pip && pip3 install pcapy-ng requests
```

## Usage
 
 ```
 # extract credentials from a pcap file
python3 ./Pcredz -f file-to-parse.pcap

# extract credentials from all pcap files in a folder
python3 ./Pcredz -d /tmp/pcap-directory-to-parse/

# extract credentials from a live packet capture on a network interface (need root privileges)
python3 ./Pcredz -i eth0 -v
```

### Options

```
  -h, --help          show this help message and exit
  -f capture.pcap     Pcap file to parse
  -d /home/pnt/pcap/  Pcap directory to parse recursivly
  -i eth0             interface for live capture
  -v                  More verbose.
  -o output_dir       Store log files in output_dir instead of the directory containing Pcredz.
```

# SSL/TLS Traffic Analysis with PCredz

## The Challenge

**PCredz cannot directly decrypt SSL/TLS (HTTPS) traffic** because:
- SSL/TLS encrypts all application data
- Credentials in HTTPS are encrypted and appear as random bytes
- You need the private key or session keys to decrypt

## Solutions to Analyze HTTPS Traffic

### Option 1: MITM Proxy (Recommended for Testing)

Use a Man-in-the-Middle proxy to decrypt and re-encrypt traffic:

#### Using mitmproxy:
```bash
# Install
pip install mitmproxy

# Start proxy
mitmproxy -w capture.mitm

# Configure browser/app to use proxy (localhost:8080)
# Install mitmproxy CA certificate in browser

# Convert to PCAP
mitmdump -r capture.mitm -w - | tcpdump -r - -w decrypted.pcap

# Analyze
python3 -m pcredz -f decrypted.pcap -v
```

#### Using Burp Suite:
1. Start Burp Suite proxy
2. Configure target to use proxy
3. Install Burp's CA certificate  
4. Export traffic as PCAP from Burp
5. Analyze with PCredz

### Option 2: Browser SSL Key Logging

For research/testing, browsers can log TLS session keys:

```bash
# Set environment variable BEFORE starting browser
export SSLKEYLOGFILE=/tmp/ssl-keys.log

# Start browser (Chrome/Firefox)
google-chrome

# Capture traffic
tcpdump -i any -w traffic.pcap

# Decrypt in Wireshark:
# Edit -> Preferences -> Protocols -> TLS
# -> (Pre)-Master-Secret log filename: /tmp/ssl-keys.log

# Export decrypted traffic as new PCAP
# File -> Export Packet Dissections -> as "PCAP"

# Analyze
python3 -m pcredz -f decrypted.pcap
```

### Option 3: Server-Side Capture (If You Control Server)

If you own the server:

```bash
# Use nginx/Apache to log decrypted traffic
# OR capture before SSL termination at load balancer

# At load balancer (before SSL):
tcpdump -i lo -w backend.pcap port 8080

# Analyze backend traffic (unencrypted)
python3 -m pcredz -f backend.pcap
```

### Option 4: Endpoint Monitoring

Instead of network capture, monitor at the endpoint:

```bash
# Linux: Use LD_PRELOAD to hook SSL functions
# Windows: Use API Monitor or Frida

# Hook openssl/gnutls read/write functions
# Log plaintext before encryption
```

## What PCredz CAN Detect in HTTPS

Even with encrypted HTTPS, PCredz can still extract:

1. **Server Name Indication (SNI)** - Unencrypted domain in ClientHello
2. **TLS Handshake Info** - Cipher suites, versions
3. **Certificate Information** - Server certificates are unencrypted
4. **Traffic Patterns** - Timing, packet sizes

But **NOT** application data (credentials, cookies, etc.)

## Recommended Workflow for Security Testing

```bash
# 1. Set up MITM proxy
mitmproxy -w test.mitm --set ssl_insecure=true

# 2. Configure target application to use proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# 3. Run your tests/application

# 4. Save traffic
mitmdump -r test.mitm -w decrypted.pcap

# 5. Analyze with PCredz
python3 -m pcredz -f decrypted.pcap -v --json --csv
```

## Legal & Ethical Considerations

⚠️ **WARNING**: 
- Only decrypt traffic you own or have explicit permission to analyze
- MITM attacks on production systems without authorization is illegal
- Use only for:
  - Your own applications during development
  - Authorized penetration testing
  - Research in isolated lab environments

## Alternative: Analyze Protocol-Specific Tools

Instead of decrypting SSL, use protocol-specific tools:

- **HTTP/HTTPS**: Browser DevTools, Burp, ZAP
- **Database TLS**: Server-side query logging
- **SSH**: AuthLog on server
- **RDP**: Windows Event Logs

Then export those logs and analyze patterns.

## Summary

| Method | Difficulty | Use Case |
|--------|-----------|----------|
| MITM Proxy | Easy | Testing your own apps |
| SSLKEYLOGFILE | Easy | Browser-based apps |
| Server-side | Medium | Own infrastructure |
| Endpoint hooks | Hard | Advanced research |

**Bottom line**: PCredz works on **plaintext network traffic only**. For HTTPS, you must decrypt it first using one of the methods above.
