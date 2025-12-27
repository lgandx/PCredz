"""
Packet handling and processing logic
Coordinates between packet decoding and parser functions
"""

import struct
import time
from ..config import PROTOCOLS
from ..utils.decoders import decode_ip_packet, decode_ipv6_packet
from . import legacy_parsers, new_protocols


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
    new_protocols.parse_cloud_credentials(data, src_ip, dst_ip, config)
    new_protocols.parse_oauth_jwt(data, src_ip, dst_ip, config)
    new_protocols.parse_api_keys(data, src_ip, dst_ip, config)
    
    # Port-specific protocol parsers
    if dst_port == 22 or src_port == 22:
        new_protocols.parse_ssh(data, src_ip, dst_ip, src_port, dst_port, config)
    
    if dst_port == 23:
        new_protocols.parse_telnet(data, src_ip, dst_ip, src_port, dst_port, config)
    
    if dst_port == 3306 or src_port == 3306:
        new_protocols.parse_mysql(data, src_ip, dst_ip, src_port, dst_port, config)
    
    if dst_port == 5432 or src_port == 5432:
        new_protocols.parse_postgresql(data, src_ip, dst_ip, src_port, dst_port, config)
    
    if dst_port == 6379 or src_port == 6379:
        new_protocols.parse_redis(data, src_ip, dst_ip, src_port, dst_port, config)
    
    if dst_port == 27017 or src_port == 27017:
        new_protocols.parse_mongodb(data, src_ip, dst_ip, src_port, dst_port, config)
    
    # Add HTTP, FTP, SMTP, etc. parsers here
    # (These will be integrated from the original ParseDataRegex function)


def print_packet_cooked(pktlen, timestamp, data, config):
    """Handle Linux cooked capture format"""
    if not data:
        return
    if data[14:16] == b'\\x08\\x00':
        decoded = decode_ip_packet(data[16:])
        src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        parse_data_regex(decoded, src_port, dst_port, config)
    
    if data[14:16] == b'\\x86\\xdd':
        decoded = decode_ipv6_packet(data[16:])
        src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        parse_data_regex(decoded, src_port, dst_port, config)


def print_packet_80211(pktlen, timestamp, data, config):
    """Handle 802.11 wireless capture format"""
    if not data:
        return
    if data[32:34] == b'\\x08\\x00':
        decoded = decode_ip_packet(data[34:])
        src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        parse_data_regex(decoded, src_port, dst_port, config)
    
    if data[32:34] == b'\\x86\\xdd':
        decoded = decode_ipv6_packet(data[34:])
        src_port = struct.unpack('>H', decoded['data'][0:2])[0]
        dst_port = struct.unpack('>H', decoded['data'][2:4])[0]
        parse_data_regex(decoded, src_port, dst_port, config)


def print_packet_tcpdump(pktlen, timestamp, data, config):
    """Handle standard tcpdump/Ethernet capture format"""
    if not data:
        return
    if data[12:14] == b'\\x08\\x00':
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
    
    if data[12:14] == b'\\x86\\xdd':
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
