"""
Packet handling and processing logic
Coordinates between packet decoding and parser functions
"""

import struct
import time
from ..config import PROTOCOLS
from ..utils.decoders import decode_ip_packet, decode_ipv6_packet
from . import http_parsers, auth_parsers, database_parsers, network_parsers, cloud_parsers


def print_packet_details(decoded, src_port, dst_port, config):
    """Print packet header details"""
    if config['timestamp']:
        ts = f'[{time.time()}] '
    else:
        ts = ''
    try:
        return f'{ts}protocol: {PROTOCOLS[decoded["protocol"]]} {decoded["source_address"]}:{src_port} > {decoded["destination_address"]}:{dst_port}'
    except:
        return f'{ts}{decoded["source_address"]}:{src_port} > {decoded["destination_address"]}:{dst_port}'


def parse_data_regex(decoded, src_port, dst_port, config):
    """Main parsing dispatcher - calls all relevant parsers"""
    src_ip = decoded['source_address']
    dst_ip = decoded['destination_address']
    data = decoded['data']
    
    # Cloud credentials detection (check all traffic)
    cloud_parsers.parse_cloud_credentials(data, src_ip, dst_ip, config)
    
    # HTTP parsers
    http_parsers.parse_http_basic(data, src_ip, dst_ip, config)
    http_parsers.parse_http_forms(data, src_ip, dst_ip, config)
    http_parsers.parse_ntlm_http(data, src_ip, dst_ip, config)
    http_parsers.parse_oauth_jwt(data, src_ip, dst_ip, config)
    http_parsers.parse_api_keys(data, src_ip, dst_ip, config)
    
    # Port-specific protocol parsers
    # SSH (22)
    if dst_port == 22 or src_port == 22:
        network_parsers.parse_ssh(data, src_ip, dst_ip, src_port, dst_port, config)
    
    # Telnet (23)
    if dst_port == 23:
        network_parsers.parse_telnet(data, src_ip, dst_ip, src_port, dst_port, config)
    
    # FTP (21)
    if dst_port == 21:
        network_parsers.parse_ftp(data, src_ip, dst_ip, config)
    
    # SMTP (25, 587)
    if dst_port == 25 or dst_port == 587:
        result = network_parsers.parse_smtp(data, config)
        if result and config['verbose']:
            print(f"{src_ip}:{src_port} > {dst_ip}:{dst_port}\n{result}")
    
    # Kerberos (88)
    if dst_port == 88:
        if PROTOCOLS.get(decoded['protocol']) == 'tcp' and len(data[20:]) > 20:
            result = auth_parsers.parse_kerberos_tcp(data[20:], config)
            if result and config['verbose']:
                print(f"{src_ip}:{src_port} > {dst_ip}:{dst_port}\n{result[0]}")
        elif PROTOCOLS.get(decoded['protocol']) == 'udp':
            result = auth_parsers.parse_kerberos_udp(data[8:], config)
            if result and config['verbose']:
                print(f"{src_ip}:{src_port} > {dst_ip}:{dst_port}\n{result[0]}")
    
    # POP3 (110)
    if dst_port == 110:
        result = network_parsers.parse_pop(data, config)
        if result and config['verbose']:
            print(f"{src_ip}:{src_port} > {dst_ip}:{dst_port}\n{result}")
    
    # IMAP (143)
    if dst_port == 143:
        result = network_parsers.parse_imap(data, config)
        if result and config['verbose']:
            print(f"{src_ip}:{src_port} > {dst_ip}:{dst_port}\n{result}")
    
    # SNMP (161)
    if dst_port == 161:
        result = auth_parsers.parse_snmp(data[8:], config)
        if result and config['verbose']:
            print(f"{src_ip}:{src_port} > {dst_ip}:{dst_port}\n{result}")
    
    # MSSQL (1433)
    if dst_port == 1433 and data[20:22] == b"\x10\x01":
        result = database_parsers.parse_mssql_plaintext(data[20:], config)
        if result and config['verbose']:
            print(f"{src_ip}:{src_port} > {dst_ip}:{dst_port}\n{result}")
    
    # MySQL (3306)
    if dst_port == 3306 or src_port == 3306:
        database_parsers.parse_mysql(data, src_ip, dst_ip, src_port, dst_port, config)
    
    # PostgreSQL (5432)
    if dst_port == 5432 or src_port == 5432:
        database_parsers.parse_postgresql(data, src_ip, dst_ip, src_port, dst_port, config)
    
    # Redis (6379)
    if dst_port == 6379 or src_port == 6379:
        database_parsers.parse_redis(data, src_ip, dst_ip, src_port, dst_port, config)
    
    # MongoDB (27017)
    if dst_port == 27017 or src_port == 27017:
        database_parsers.parse_mongodb(data, src_ip, dst_ip, src_port, dst_port, config)


def print_packet_cooked(pktlen, timestamp, data, config):
    """Handle Linux cooked capture format"""
    if not data:
        return
    if data[14:16] == b'\x08\x00':
        decoded = decode_ip_packet(data[16:])
        src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        parse_data_regex(decoded, src_port, dst_port, config)
    
    if data[14:16] == b'\x86\xdd':
        decoded = decode_ipv6_packet(data[16:])
        src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        parse_data_regex(decoded, src_port, dst_port, config)


def print_packet_80211(pktlen, timestamp, data, config):
    """Handle 802.11 wireless capture format"""
    if not data:
        return
    if data[32:34] == b'\x08\x00':
        decoded = decode_ip_packet(data[34:])
        src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        parse_data_regex(decoded, src_port, dst_port, config)
    
    if data[32:34] == b'\x86\xdd':
        decoded = decode_ipv6_packet(data[34:])
        src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        parse_data_regex(decoded, src_port, dst_port, config)


def print_packet_tcpdump(pktlen, timestamp, data, config):
    """Handle standard tcpdump/Ethernet capture format"""
    if not data:
        return
    if data[12:14] == b'\x08\x00':
        decoded = decode_ip_packet(data[14:])
        if len(decoded['data']) >= 2:
            src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        else:
            src_port = 0
        if len(decoded['data']) > 2:
            dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        else:
            dst_port = 0
        parse_data_regex(decoded, src_port, dst_port, config)
    
    if data[12:14] == b'\x86\xdd':
        decoded = decode_ipv6_packet(data[14:])
        if len(decoded['data']) >= 2:
            src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        else:
            src_port = 0
        if len(decoded['data']) > 2:
            dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        else:
            dst_port = 0
        parse_data_regex(decoded, src_port, dst_port, config)
