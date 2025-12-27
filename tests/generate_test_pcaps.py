#!/usr/bin/env python3
"""
Generate test PCAP files for PCredz testing
Creates fake network traffic for various protocols
"""

import sys
import os

try:
    from scapy.all import *
except ImportError:
    print("Scapy not installed. Installing...")
    os.system("pip3 install scapy")
    from scapy.all import *

def generate_http_basic_auth():
    """Generate HTTP Basic Authentication traffic"""
    import base64
    
    # Encode credentials
    creds = base64.b64encode(b"admin:password123").decode()
    
    # HTTP GET request with Basic Auth
    packets = []
    
    # SYN
    syn = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="S")
    packets.append(syn)
    
    # SYN-ACK
    synack = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=80, dport=54321, flags="SA")
    packets.append(synack)
    
    # ACK
    ack = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="A")
    packets.append(ack)
    
    # HTTP Request with Basic Auth
    http_req = f"GET /admin HTTP/1.1\\r\\nHost: example.com\\r\\nAuthorization: Basic {creds}\\r\\n\\r\\n"
    http_pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54321, dport=80, flags="PA") / Raw(load=http_req)
    packets.append(http_pkt)
    
    return packets

def generate_ftp_traffic():
    """Generate  FTP authentication traffic"""
    packets = []
    
    # FTP USER command
    ftp_user = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54322, dport=21, flags="PA") / Raw(load=b"USER john\\r\\n")
    packets.append(ftp_user)
    
    # FTP PASS command
    ftp_pass = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54322, dport=21, flags="PA") / Raw(load=b"PASS secret123\\r\\n")
    packets.append(ftp_pass)
    
    return packets

def generate_telnet_traffic():
    """Generate Telnet plaintext credentials"""
    packets = []
    
    # Login prompt
    telnet_login = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=23, dport=54323, flags="PA") / Raw(load=b"login: ")
    packets.append(telnet_login)
    
    # Username response
    telnet_user = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54323, dport=23, flags="PA") / Raw(load=b"root\\r\\n")
    packets.append(telnet_user)
    
    # Password prompt
    telnet_pass_prompt = IP(src="192.168.1.1", dst="192.168.1.100") / TCP(sport=23, dport=54323, flags="PA") / Raw(load=b"Password: ")
    packets.append(telnet_pass_prompt)
    
    # Password response
    telnet_pass = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54323, dport=23, flags="PA") / Raw(load=b"toor\\r\\n")
    packets.append(telnet_pass)
    
    return packets

def generate_smtp_traffic():
    """Generate SMTP authentication"""
    import base64
    packets = []
    
    # SMTP AUTH
    smtp_auth = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54324, dport=587, flags="PA") / Raw(load=b"AUTH PLAIN\\r\\n")
    packets.append(smtp_auth)
    
    # Base64 encoded credentials (user@example.com\\x00user@example.com\\x00password)
    creds_b64 = base64.b64encode(b"\\x00user@example.com\\x00emailpass").decode()
    smtp_creds = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54324, dport=587, flags="PA") / Raw(load=f"{creds_b64}\\r\\n".encode())
    packets.append(smtp_creds)
    
    return packets

def generate_redis_traffic():
    """Generate Redis AUTH command"""
    packets = []
    
    # Redis AUTH
    redis_auth = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54325, dport=6379, flags="PA") / Raw(load=b"*2\\r\\n$4\\r\\nAUTH\\r\\n$10\\r\\nredispass1\\r\\n")
    packets.append(redis_auth)
    
    return packets

def generate_http_form_login():
    """Generate HTTP form-based login"""
    packets = []
    
    # POST request with form data
    form_data = "username=alice&password=wonderland123"
    http_post = f"POST /login HTTP/1.1\\r\\nHost: example.com\\r\\nContent-Type: application/x-www-form-urlencoded\\r\\nContent-Length: {len(form_data)}\\r\\n\\r\\n{form_data}"
    
    post_pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54326, dport=80, flags="PA") / Raw(load=http_post)
    packets.append(post_pkt)
    
    return packets

def generate_cloud_credentials():
    """Generate traffic with cloud credentials"""
    packets = []
    
    # AWS keys in HTTP request
    aws_request = "GET /api/config HTTP/1.1\\r\\nHost: api.example.com\\r\\nX-API-Key: AKIAIOSFODNN7EXAMPLE\\r\\n\\r\\n"
    aws_pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54327, dport=443, flags="PA") / Raw(load=aws_request)
    packets.append(aws_pkt)
    
    # GitHub token
    github_request = "GET /repos HTTP/1.1\\r\\nHost: api.github.com\\r\\nAuthorization: token ghp_1234567890abcdefghijklmnopqrstuv1234\\r\\n\\r\\n"
    github_pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54328, dport=443, flags="PA") / Raw(load=github_request)
    packets.append(github_pkt)
    
    return packets

def generate_jwt_traffic():
    """Generate traffic with JWT tokens"""
    packets = []
    
    # JWT in Authorization header
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    jwt_request = f"GET /api/user HTTP/1.1\\r\\nHost: api.example.com\\r\\nAuthorization: Bearer {jwt}\\r\\n\\r\\n"
    jwt_pkt = IP(src="192.168.1.100", dst="192.168.1.1") / TCP(sport=54329, dport=443, flags="PA") / Raw(load=jwt_request)
    packets.append(jwt_pkt)
    
    return packets

def generate_snmp_traffic():
    """Generate SNMP community string traffic"""
    packets = []
    
    # SNMP v1 GET request with community string "public"
    # Simplified SNMP packet structure
    snmp_pkt = IP(src="192.168.1.100", dst="192.168.1.1") / UDP(sport=54330, dport=161) / Raw(load=b"\\x30\\x26\\x02\\x01\\x00\\x04\\x06public\\xa0\\x19\\x02\\x04\\x1e\\x8c\\x5f\\x3a\\x02\\x01\\x00\\x02\\x01\\x00\\x30\\x0b\\x30\\x09\\x06\\x05\\x2b\\x06\\x01\\x02\\x01\\x05\\x00")
    packets.append(snmp_pkt)
    
    return packets

def main():
    """Generate all test PCAPs"""
    output_dir = "tests"
    os.makedirs(output_dir, exist_ok=True)
    
    all_packets = []
    
    print("[+] Generating test PCAP files...")
    
    # Generate individual protocol PCAPs
    protocols = {
        'http_basic': generate_http_basic_auth(),
        'ftp': generate_ftp_traffic(),
        'telnet': generate_telnet_traffic(),
        'smtp': generate_smtp_traffic(),
        'redis': generate_redis_traffic(),
        'http_form': generate_http_form_login(),
        'cloud_creds': generate_cloud_credentials(),
        'jwt': generate_jwt_traffic(),
        'snmp': generate_snmp_traffic(),
    }
    
    for name, packets in protocols.items():
        filename = os.path.join(output_dir, f"{name}.pcap")
        wrpcap(filename, packets)
        print(f"  [✓] Created {filename} ({len(packets)} packets)")
        all_packets.extend(packets)
    
    # Create combined sample.pcap
    combined_file = os.path.join(output_dir, "sample.pcap")
    wrpcap(combined_file, all_packets)
    print(f"\\n[+] Created combined sample: {combined_file} ({len(all_packets)} packets total)")
    
    # Create README
    readme = """# Test PCAP Files

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
"""
    
    readme_file = os.path.join(output_dir, "README.md")
    with open(readme_file, 'w') as f:
        f.write(readme)
    print(f"[+] Created {readme_file}")
    
    print("\\n✅ Test PCAP generation complete!")
    print(f"\\nTest with: python3 -m pcredz -f {combined_file} -v")

if __name__ == '__main__':
    main()
