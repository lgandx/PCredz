# PCredz 2.1.0

PCredz extracts credentials and authentication tokens from network traffic (PCAP files or live capture).

## Features

### Supported Protocols

Extract credentials from both IPv4 and IPv6 traffic:

- **NTLM**: NTLMv1/v2 hashes from HTTP, SMB, LDAP, MSSQL, DCE-RPC, and more
- **Kerberos**: AS-REQ Pre-Auth (etype 23) hashes
- **HTTP**: Basic authentication, form fields (passwords, API keys, tokens)
- **FTP**: USER/PASS commands
- **IRC**: NICK/USER/PASS authentication
- **SMTP**: AUTH PLAIN and AUTH LOGIN
- **IMAP**: LOGIN authentication
- **POP3**: USER/PASS commands
- **LDAP**: Simple Bind (plaintext passwords)
- **SNMP**: Community strings (v1/v2c)
- **MSSQL**: TDS protocol authentication
- **Credit Cards**: Card number extraction (optional)

### Output Formats

- **Hashcat compatible**: All hashes formatted for direct use with hashcat
  - NTLMv1: `-m 5500`
  - NTLMv2: `-m 5600`
  - Kerberos: `-m 7500`
- **Organized logs**: Separate files for each credential type in `logs/` directory
- **Session log**: Complete timeline in `CredentialDump-Session.log`
- **Deduplication**: Same credentials only logged once (unless `-v` flag used)

### Link Layer Support

- **Ethernet** (DLT_EN10MB)
- **Linux Cooked Capture** (DLT_LINUX_SLL)
- **Raw IP** (DLT_RAW)
- **Automatic detection** of link layer type

## Installation

### Docker (Recommended)

```bash
# Build the container
docker build -t pcredz .

# Run with current directory mounted
docker run --rm -v $(pwd):/data pcredz -f /data/capture.pcap

# For live capture (requires --net=host)
docker run --rm --net=host -v $(pwd):/data pcredz -i eth0 -v
```

### Linux

**Debian/Ubuntu:**
```bash
sudo apt-get install python3-pip libpcap-dev
pip3 install pcapy-ng
```

**Fedora/RHEL:**
```bash
sudo dnf install python3-pip libpcap-devel
pip3 install pcapy-ng
```

**Arch Linux:**
```bash
sudo pacman -S python-pip libpcap
pip3 install pcapy-ng
```

## Usage

### Basic Examples

```bash
# Parse a single PCAP file
./Pcredz -f capture.pcap

# Parse all PCAP files in a directory (recursive)
./Pcredz -d /path/to/pcap/directory/

# Live capture on an interface (requires root)
sudo ./Pcredz -i eth0

# Verbose mode (show duplicate credentials)
./Pcredz -f capture.pcap -v

# Custom output directory
./Pcredz -f capture.pcap -o /tmp/pcredz-output/
```

### Options

```
Required (choose one):
  -f FILE         PCAP file to parse
  -d DIR          Directory to parse recursively
  -i INTERFACE    Interface for live capture

Optional:
  -v              Verbose mode (print duplicate credentials)
  -t              Print timestamps
  -o DIR          Output directory for logs (default: ./)
  -c              Disable credit card scanning
  -h              Show help message
```

### Output Files

All credentials are saved to the `logs/` directory:

```
logs/
├── NTLMv1.txt              # NTLMv1 hashes (hashcat -m 5500)
├── NTLMv2.txt              # NTLMv2 hashes (hashcat -m 5600)
├── MSKerb.txt              # Kerberos hashes (hashcat -m 7500)
├── HTTP-Basic.txt          # HTTP Basic auth credentials
├── HTTP-PasswordFields.txt # HTTP form fields and API keys
├── FTP-Plaintext.txt       # FTP credentials
├── IRC-Plaintext.txt       # IRC credentials
├── SMTP-Plaintext.txt      # SMTP credentials
├── LDAP-Simple.txt         # LDAP Simple Bind credentials
├── MSSQL-Plaintext.txt     # MSSQL credentials
└── SNMPv1.txt              # SNMP community strings
```

Plus a session log:
```
CredentialDump-Session.log  # Complete session with timestamps
```

## Examples

### Extract NTLM Hashes

```bash
./Pcredz -f capture.pcap

# Output:
# 192.168.1.10:445 > 192.168.1.20:1024
# NTLMv2 complete hash is: admin::DOMAIN:1122334455667788:ABC123...

# Use with hashcat:
hashcat -m 5600 logs/NTLMv2.txt wordlist.txt
```

### Live Capture

```bash
sudo ./Pcredz -i eth0 -v

# Captures and displays credentials in real-time
# Press Ctrl+C to stop
```

### Bulk Processing

```bash
# Process all PCAPs in a directory tree
./Pcredz -d /forensics/network-captures/

# Parsing /forensics/network-captures/day1/morning.pcap...
# Parsing /forensics/network-captures/day1/afternoon.pcap...
# ...
```

## Performance

### Optimizations

- **File I/O caching**: Avoids redundant file reads (10-100x speedup)
- **Regex pre-compilation**: Compiled patterns cached (2-5x speedup)
- **Smart deduplication**: In-memory tracking of seen credentials
- **Link layer detection**: Auto-detects and caches offset (minimal overhead)

### Benchmarks

Typical performance on modern hardware:

- **Small files** (<10MB): <1 second
- **Medium files** (100MB): 5-10 seconds
- **Large files** (1GB+): 1-2 minutes
- **Live capture**: 5,000-10,000 packets/second

## Troubleshooting

### pcapy-ng Not Found

```bash
pip3 install pcapy-ng
# If that fails:
pip3 install --break-system-packages pcapy-ng
```

### Permission Denied (Live Capture)

Live capture requires root privileges:
```bash
sudo ./Pcredz -i eth0
```

### No Credentials Found

- Verify the PCAP contains the expected protocols (use Wireshark)
- Check that traffic isn't encrypted (HTTPS, SSH, etc.)
- Try verbose mode (`-v`) to see all activity
- Check the link layer type is supported

## Contributing

Found a bug or want to add a feature? Contributions welcome!

1. Test your changes thoroughly
2. Follow the existing code style
3. Add examples for new features
4. Update documentation

## License

GNU General Public License v3.0

## Author

**Laurent Gaffie**
- Email: lgaffie@secorizon.com
- X/Twitter: [@secorizon](https://x.com/secorizon)
- GitHub: [lgandx/PCredz](https://github.com/lgandx/)

