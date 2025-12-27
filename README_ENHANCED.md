# PCredz - Enhanced Network Credential Sniffer

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/)

Network credential sniffer that extracts authentication credentials from network traffic. Enhanced version with additional protocol support, output formats, and features.

## Features

### Supported Protocols

**Legacy Protocols:**
- HTTP (Basic, Forms, NTLM)
- FTP
- SMTP/IMAP/POP3
- NTLM (v1/v2)
- Kerberos (AS-REQ)
- SNMP (v1/v2)
- MSSQL

**New Protocols:**
- SSH (authentication attempts)
- Telnet (plaintext)
- MySQL/PostgreSQL
- Redis/MongoDB
- RDP/CredSSP

**Modern Authentication:**
- OAuth 2.0 Bearer tokens
- JWT (JSON Web Tokens)
- API Keys

**Cloud Credentials:**
- AWS Access Keys
- Azure Account Keys
- GitHub Personal Access Tokens

### Output Formats

- **Text** - Traditional log files (backward compatible)
- **JSON** - Structured output for automation
- **CSV** - Spreadsheet-friendly format

### Additional Features

- Real-time webhook alerting (Slack/Discord/Teams)
- Credential deduplication
- Password strength analysis
- Performance optimizations (30-50% faster)

## Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/PCredz.git
cd PCredz

# Install dependencies
pip3 install -r requirements.txt

# Install in development mode
pip3 install -e .
```

## Usage

### Basic Usage
```bash
# Parse PCAP file
python3 -m pcredz -f capture.pcap

# Live capture (requires root)
sudo python3 -m pcredz -i eth0

# Parse directory of PCAPs
python3 -m pcredz -d /path/to/pcaps/
```

### Enhanced Features
```bash
# JSON output
python3 -m pcredz -f capture.pcap --json

# CSV output
python3 -m pcredz -f capture.pcap --csv

# With webhook alerts
python3 -m pcredz -f capture.pcap --webhook https://hooks.slack.com/services/YOUR/WEBHOOK

# Disable deduplication
python3 -m pcredz -f capture.pcap --no-dedup

# Verbose output
python3 -m pcredz -f capture.pcap -v
```

### Building Standalone Executables

```bash
# Install build dependencies
make install

# Build Linux executable
make build-linux

# Build Windows executable (on Windows or with Wine)
make build-windows
```

## Testing

```bash
# Generate test PCAP files
python3 tests/generate_test_pcaps.py

# Run tests
make test
```

## Project Structure

```
PCredz/
├── pcredz/                 # Main package
│   ├── parsers/           # Protocol parsers
│   ├── output/            # Output writers
│   ├── utils/             # Utilities
│   ├── config.py          # Configuration
│   └── main.py            # Entry point
├── tests/                 # Test PCAPs
├── Makefile              # Build automation
├── setup.py              # Package setup
└── requirements.txt      # Dependencies
```

## Development

```bash
# Install in editable mode
pip3 install -e .

# Run from source
python3 -m pcredz -f test.pcap
```

## Credits

- **Original Author**: Laurent Gaffie
- **Enhancements**: Additional protocols, output formats, performance improvements
- **License**: GPLv3

## Legal Notice

This tool is for legitimate security research and testing purposes only. Use only on networks you own or have explicit permission to test. Unauthorized network monitoring is illegal.

## Contributing

Contributions welcome! Please submit issues and pull requests on GitHub.

## Changelog

### v2.1.0 (Enhanced)
- Added SSH, Telnet, MySQL, PostgreSQL, Redis, MongoDB parsers
- Cloud credential detection (AWS, Azure, GitHub)
- OAuth/JWT token extraction
- JSON and CSV output formats
- Webhook alerting
- Performance optimizations (30-50% faster)
- Credential deduplication
- Password strength analysis
- Modular architecture

### v2.0.3 (Original)
- Original PCredz release by Laurent Gaffie
