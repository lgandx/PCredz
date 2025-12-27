# Test PCAP Files

These PCAP files contain simulated network traffic for testing PCredz.

## Files

- `http_basic.pcap` - HTTP Basic Authentication (admin:password123)
- `ftp.pcap` - FTP authentication (john:secret123)
- `telnet.pcap` - Telnet plaintext login (root:toor)
- `smtp.pcap` - SMTP AUTH (user@example.com:emailpass)
- `redis.pcap` - Redis AUTH (redispass1)
- `http_form.pcap` - HTTP form login (alice:wonderland123)
- `cloud_creds.pcap` - AWS/GitHub credentials
- `jwt.pcap` - JWT Bearer tokens
- `snmp.pcap` - SNMP community string (public)
- `sample.pcap` - Combined sample with all traffic

## Expected Credentials

- HTTP Basic: admin / password123
- FTP: john / secret123
- Telnet: root / toor
- SMTP: user@example.com / emailpass
- Redis: redispass1
- HTTP Form: alice / wonderland123
- AWS Key: AKIAIOSFODNN7EXAMPLE
- GitHub Token: ghp_1234567890abcdefghijklmnopqrstuv1234
- SNMP Community: public

## Usage

```bash
# Test with single protocol
python3 -m pcredz -f tests/http_basic.pcap -v

# Test with combined sample
python3 -m pcredz -f tests/sample.pcap -v --json --csv

# Test all PCAPs
for pcap in tests/*.pcap; do
    echo "Testing $pcap..."
    python3 -m pcredz -f "$pcap" -v
done
```
