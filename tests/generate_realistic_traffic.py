#!/usr/bin/env python3
"""
Generate realistic comprehensive PCAP file simulating real network traffic
Includes proper TCP handshakes, normal traffic, and credentials
"""

import sys
import os
import random
import time

try:
    from scapy.all import *
except ImportError:
    print("Scapy not installed. Installing...")
    os.system("pip3 install scapy")
    from scapy.all import *


class NetworkSimulator:
    """Simulate realistic network traffic"""
    
    def __init__(self):
        self.packets = []
        self.seq_nums = {}  # Track sequence numbers per connection
        self.timestamp = time.time()
        
    def add_packet(self, pkt, delay=0.001):
        """Add packet with realistic timestamp"""
        self.timestamp += delay + random.uniform(0, 0.01)
        pkt.time = self.timestamp
        self.packets.append(pkt)
    
    def tcp_handshake(self, src_ip, dst_ip, src_port, dst_port):
        """Simulate TCP 3-way handshake"""
        # SYN
        syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
        self.add_packet(syn, 0.001)
        
        # SYN-ACK
        synack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001)
        self.add_packet(synack, 0.05)
        
        # ACK
        ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001)
        self.add_packet(ack, 0.001)
        
        # Store sequence numbers
        conn_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        self.seq_nums[conn_id] = {"seq": 1001, "ack": 2001}
        
        return conn_id
    
    def send_data(self, conn_id, src_ip, dst_ip, src_port, dst_port, data):
        """Send data over established connection"""
        seq_info = self.seq_nums.get(conn_id, {"seq": 1001, "ack": 2001})
        
        # Data packet
        pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", 
                                                seq=seq_info["seq"], ack=seq_info["ack"]) / Raw(load=data)
        self.add_packet(pkt, 0.01)
        
        # Update sequence number
        seq_info["seq"] += len(data)
        
        # ACK from server
        ack_pkt = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="A",
                                                     seq=seq_info["ack"], ack=seq_info["seq"])
        self.add_packet(ack_pkt, 0.02)
    
    def tcp_close(self, conn_id, src_ip, dst_ip, src_port, dst_port):
        """Properly close TCP connection"""
        seq_info = self.seq_nums.get(conn_id, {"seq": 1001, "ack": 2001})
        
        # FIN from client
        fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA",
                                                seq=seq_info["seq"], ack=seq_info["ack"])
        self.add_packet(fin, 0.01)
        
        # FIN-ACK from server
        finack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA",
                                                   seq=seq_info["ack"], ack=seq_info["seq"]+1)
        self.add_packet(finack, 0.02)
        
        # Final ACK
        final_ack = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A",
                                                      seq=seq_info["seq"]+1, ack=seq_info["ack"]+1)
        self.add_packet(final_ack, 0.001)
    
    def add_normal_traffic(self):
        """Add normal background traffic (DNS, HTTPS negotiation, etc.)"""
        # DNS query
        dns_query = IP(src="192.168.1.100", dst="8.8.8.8") / UDP(sport=53124, dport=53) / \
                    DNS(rd=1, qd=DNSQR(qname="google.com"))
        self.add_packet(dns_query, 0.1)
        
        # DNS response
        dns_resp = IP(src="8.8.8.8", dst="192.168.1.100") / UDP(sport=53, dport=53124) / \
                   DNS(qr=1, aa=1, qd=DNSQR(qname="google.com"), an=DNSRR(rrname="google.com", rdata="142.250.185.78"))
        self.add_packet(dns_resp, 0.05)
        
        # TLS handshake fragments (HTTPS traffic - encrypted, no credentials visible)
        conn = self.tcp_handshake("192.168.1.100", "142.250.185.78", 54230, 443)
        tls_hello = b"\x16\x03\x01\x00\x9c\x01\x00\x00\x98\x03\x03" + os.urandom(32)
        self.send_data(conn, "192.168.1.100", "142.250.185.78", 54230, 443, tls_hello)
        self.tcp_close(conn, "192.168.1.100", "142.250.185.78", 54230, 443)
    
    def add_http_basic_auth(self):
        """HTTP Basic Authentication"""
        import base64
        conn = self.tcp_handshake("192.168.1.100", "10.0.0.50", 54231, 80)
        
        # HTTP GET with Basic Auth
        creds = base64.b64encode(b"admin:SuperSecret123").decode()
        http_req = f"GET /admin/dashboard HTTP/1.1\r\nHost: intranet.company.local\r\nAuthorization: Basic {creds}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        self.send_data(conn, "192.168.1.100", "10.0.0.50", 54231, 80, http_req.encode())
        
        # HTTP Response
        http_resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Welcome Admin</html>"
        self.send_data(conn, "10.0.0.50", "192.168.1.100", 80, 54231, http_resp)
        
        self.tcp_close(conn, "192.168.1.100", "10.0.0.50", 54231, 80)
    
    def add_ftp_session(self):
        """Complete FTP session"""
        conn = self.tcp_handshake("192.168.1.100", "10.0.0.100", 54232, 21)
        
        # FTP banner
        banner = b"220 FTP Server Ready\r\n"
        self.send_data(conn, "10.0.0.100", "192.168.1.100", 21, 54232, banner)
        
        # USER command
        user_cmd = b"USER john.doe\r\n"
        self.send_data(conn, "192.168.1.100", "10.0.0.100", 54232, 21, user_cmd)
        
        # Password prompt
        pass_prompt = b"331 Password required\r\n"
        self.send_data(conn, "10.0.0.100", "192.168.1.100", 21, 54232, pass_prompt)
        
        # PASS command
        pass_cmd = b"PASS P@ssw0rd2024!\r\n"
        self.send_data(conn, "192.168.1.100", "10.0.0.100", 54232, 21, pass_cmd)
        
        # Success
        success = b"230 User logged in\r\n"
        self.send_data(conn, "10.0.0.100", "192.168.1.100", 21, 54232, success)
        
        self.tcp_close(conn, "192.168.1.100", "10.0.0.100", 54232, 21)
    
    def add_http_form_login(self):
        """HTTP POST with form credentials"""
        conn = self.tcp_handshake("192.168.1.100", "10.0.0.50", 54233, 80)
        
        # POST request
        form_data = "email=alice.smith%40company.com&password=W!nterIsComing2024&remember=true"
        http_post = f"POST /api/auth/login HTTP/1.1\r\nHost: app.company.local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(form_data)}\r\n\r\n{form_data}"
        self.send_data(conn, "192.168.1.100", "10.0.0.50", 54233, 80, http_post.encode())
        
        # Response with session cookie
        http_resp = b"HTTP/1.1 200 OK\r\nSet-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MTYxNjI2NTIwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\r\n\r\n{\"success\":true}"
        self.send_data(conn, "10.0.0.50", "192.168.1.100", 80, 54233, http_resp)
        
        self.tcp_close(conn, "192.168.1.100", "10.0.0.50", 54233, 80)
    
    def add_telnet_session(self):
        """Telnet session with credentials"""
        conn = self.tcp_handshake("192.168.1.100", "10.0.0.200", 54234, 23)
        
        # Login prompt
        login_prompt = b"\xff\xfd\x18\xff\xfd\x20\xff\xfd\x23\xff\xfd\x27login: "
        self.send_data(conn, "10.0.0.200", "192.168.1.100", 23, 54234, login_prompt)
        
        # Username
        username = b"root\r\n"
        self.send_data(conn, "192.168.1.100", "10.0.0.200", 54234, 23, username)
        
        # Password prompt
        pass_prompt = b"Password: "
        self.send_data(conn, "10.0.0.200", "192.168.1.100", 23, 54234, pass_prompt)
        
        # Password
        password = b"toor123\r\n"
        self.send_data(conn, "192.168.1.100", "10.0.0.200", 54234, 23, password)
        
        # Welcome message
        welcome = b"\r\nWelcome to Ubuntu Server\r\n# "
        self.send_data(conn, "10.0.0.200", "192.168.1.100", 23, 54234, welcome)
        
        self.tcp_close(conn, "192.168.1.100", "10.0.0.200", 54234, 23)
    
    def add_redis_auth(self):
        """Redis authentication"""
        conn = self.tcp_handshake("192.168.1.100", "10.0.0.150", 54235, 6379)
        
        # AUTH command
        auth_cmd = b"*2\r\n$4\r\nAUTH\r\n$15\r\nRedis#Secure99\r\n"
        self.send_data(conn, "192.168.1.100", "10.0.0.150", 54235, 6379, auth_cmd)
        
        # OK response
        ok_resp = b"+OK\r\n"
        self.send_data(conn, "10.0.0.150", "192.168.1.100", 6379, 54235, ok_resp)
        
        self.tcp_close(conn, "192.168.1.100", "10.0.0.150", 54235, 6379)
    
    def add_cloud_credentials(self):
        """HTTP requests with cloud credentials"""
        conn = self.tcp_handshake("192.168.1.100", "10.0.0.50", 54236, 443)
        
        # AWS API call with access key
        aws_req = b"GET /api/resources HTTP/1.1\r\nHost: api.internal.company.com\r\nX-API-Key: AKIAIOSFODNN7EXAMPLEKEY\r\nAuthorization: AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240127\r\n\r\n"
        self.send_data(conn, "192.168.1.100", "10.0.0.50", 54236, 443, aws_req)
        
        self.tcp_close(conn, "192.168.1.100", "10.0.0.50", 54236, 443)
        
        # GitHub API with token
        conn2 = self.tcp_handshake("192.168.1.100", "10.0.0.50", 54237, 443)
        github_req = b"GET /repos HTTP/1.1\r\nHost: api.github.company.com\r\nAuthorization: token ghp_Ab3dEf9Gh1JkLm2nOpQrSt3UvWxYz0Ab3dE\r\n\r\n"
        self.send_data(conn2, "192.168.1.100", "10.0.0.50", 54237, 443, github_req)
        self.tcp_close(conn2, "192.168.1.100", "10.0.0.50", 54237, 443)
    
    def add_smtp_auth(self):
        """SMTP authentication"""
        conn = self.tcp_handshake("192.168.1.100", "10.0.0.25", 54238, 587)
        
        # SMTP banner
        banner = b"220 mail.company.local ESMTP\r\n"
        self.send_data(conn, "10.0.0.25", "192.168.1.100", 587, 54238, banner)
        
        # EHLO
        ehlo = b"EHLO client.company.local\r\n"
        self.send_data(conn, "192.168.1.100", "10.0.0.25", 54238, 587, ehlo)
        
        # AUTH PLAIN
        import base64
        auth_plain = base64.b64encode(b"\x00noreply@company.com\x00Email#Pass2024").decode()
        auth_cmd = f"AUTH PLAIN {auth_plain}\r\n".encode()
        self.send_data(conn, "192.168.1.100", "10.0.0.25", 54238, 587, auth_cmd)
        
        # Auth success
        success = b"235 Authentication successful\r\n"
        self.send_data(conn, "10.0.0.25", "192.168.1.100", 587, 54238, success)
        
        self.tcp_close(conn, "192.168.1.100", "10.0.0.25", 54238, 587)
    
    def generate_comprehensive_pcap(self):
        """Generate realistic comprehensive PCAP"""
        print("[+] Generating comprehensive network traffic simulation...")
        print("    Simulating realistic network activity with embedded credentials\n")
        
        # Add realistic mix of traffic
        self.add_normal_traffic()
        print("  [✓] Background DNS/HTTPS traffic")
        
        self.add_http_basic_auth()
        print("  [✓] HTTP Basic Auth (admin:SuperSecret123)")
        
        self.add_normal_traffic()  # More normal traffic
        
        self.add_ftp_session()
        print("  [✓] FTP Session (john.doe:P@ssw0rd2024!)")
        
        self.add_normal_traffic()
        
        self.add_http_form_login()
        print("  [✓] HTTP Form Login (alice.smith@company.com:W!nterIsComing2024)")
        
        self.add_telnet_session()
        print("  [✓] Telnet Session (root:toor123)")
        
        self.add_normal_traffic()
        
        self.add_redis_auth()
        print("  [✓] Redis AUTH (Redis#Secure99)")
        
        self.add_cloud_credentials()
        print("  [✓] AWS/GitHub credentials")
        
        self.add_smtp_auth()
        print("  [✓] SMTP AUTH (noreply@company.com:Email#Pass2024)")
        
        self.add_normal_traffic()
        
        # Save to file
        output_file = "tests/realistic_network_traffic.pcap"
        wrpcap(output_file, self.packets)
        
        print(f"\n[+] Generated {len(self.packets)} packets")
        print(f"[+] Saved to: {output_file}")
        print(f"[+] File size: {os.path.getsize(output_file)} bytes\n")
        
        # Summary
        print("=" * 60)
        print("EXPECTED CREDENTIALS TO BE EXTRACTED:")
        print("=" * 60)
        print("1. HTTP Basic Auth:")
        print("   - Username: admin")
        print("   - Password: SuperSecret123")
        print("\n2. FTP:")
        print("   - Username: john.doe")
        print("   - Password: P@ssw0rd2024!")
        print("\n3. HTTP Form Login:")
        print("   - Email: alice.smith@company.com")
        print("   - Password: W!nterIsComing2024")
        print("\n4. Telnet:")
        print("   - Username: root")
        print("   - Password: toor123")
        print("\n5. Redis:")
        print("   - Password: Redis#Secure99")
        print("\n6. Cloud Credentials:")
        print("   - AWS Key: AKIAIOSFODNN7EXAMPLEKEY")
        print("   - GitHub Token: ghp_Ab3dEf9Gh1JkLm2nOpQrSt3UvWxYz0Ab3dE")
        print("\n7. SMTP:")
        print("   - Email: noreply@company.com")
        print("   - Password: Email#Pass2024")
        print("=" * 60)
        
        return output_file


def main():
    sim = NetworkSimulator()
    pcap_file = sim.generate_comprehensive_pcap()
    
    print(f"\n✅ Realistic network traffic PCAP generated successfully!")
    print(f"\nTest with:")
    print(f"  python3 -m pcredz -f {pcap_file} -v")
    print(f"  python3 -m pcredz -f {pcap_file} --json --csv")


if __name__ == '__main__':
    main()
