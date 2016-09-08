#Features:

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

#Install:

###Linux:

On a debian based OS: 
```bash
sudo apt-get install python-pip
sudo pip install pypcap
```
Test if pcap is installed
```bash
python -c "help('pcap');" | grep pcap     

or

Simply open Python and type:
import pcap
```

###Os X and other distributions: 

```bash
wget http://downloads.sourceforge.net/project/pylibpcap/pylibpcap/0.6.4/pylibpcap-0.6.4.tar.gz

tar xvf pylibpcap-0.6.4.tar.gz

cd pylibpcap-0.6.4

python setup.py install
```


#Usage:
 
```bash 
./Pcredz -f file-to-parse.pcap

./Pcredz -d /tmp/pcap-directory-to-parse/

./Pcredz -i eth0
```

#Options:
```bash
  -h, --help          show this help message and exit

  -f capture.pcap     Pcap file to parse

  -d /home/pnt/pcap/  Pcap directory to parse recursivly

  -i eth0             interface for live capture

  -v                  More verbose.
```


