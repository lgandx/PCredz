# PCredz

This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

## Features

- Extract from a pcap file or from a live interface:
  - Credit card numbers
  - POP
  - SMTP
  - IMAP
  - SNMP community string
  - FTP
  - HTTP
  - NTLMv1/v2 (DCE-RPC,SMBv1/2,LDAP, MSSQL, HTTP, etc)
  - Kerberos (AS-REQ Pre-Auth etype 23) hashes.

- All hashes are displayed in a hashcat format (use -m 7500 for kerberos, -m 5500 for NTLMv1, -m 5600 for NTLMv2).
- Log all credentials to a file (CredentialDump-Session.log).

## Install

### Linux

On a debian based OS bash:

```bash
apt-get install python-libpcap
```

Note: You might need to use a previous libpcap version on some distribution:

```bash
wget http://mirrors.kernel.org/ubuntu/pool/universe/p/python-libpcap/python-libpcap_0.6.4-1_amd64.deb && dpkg -i python-libpcap_0.6.4-1_amd64.deb
```

On Kali, you will need to:

```bash
apt-get remove python-pypcap && apt-get install python-libpcap
```

### OSX and other distributions

```bash
wget http://downloads.sourceforge.net/project/pylibpcap/pylibpcap/0.6.4/pylibpcap-0.6.4.tar.gz
tar xvf pylibpcap-0.6.4.tar.gz
cd pylibpcap-0.6.4
python setup.py install
```

## Usage
 
 ```
 # extract credentials from a pcap file
./Pcredz -f file-to-parse.pcap

# extract credentials from all pcap files in a folder
./Pcredz -d /tmp/pcap-directory-to-parse/

# extract credentials from a live packet capture on a network interface
./Pcredz -i eth0
```

### Options

```bash
  -h, --help          show this help message and exit
  -f capture.pcap     Pcap file to parse
  -d /home/pnt/pcap/  Pcap directory to parse recursivly
  -i eth0             interface for live capture
  -v                  More verbose.
```

