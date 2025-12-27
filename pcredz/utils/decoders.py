"""Packet decoding utilities"""

import socket
import struct


def decode_ip_packet(s):
    """Decode IPv4 packet"""
    d = {}
    d['version'] = (s[0] & 0xf0) >> 4
    d['header_len'] = s[0] & 0x0f
    d['tos'] = s[1]
    d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
    d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
    d['flags'] = (s[6] & 0xe0) >> 5
    d['fragment_offset'] = socket.ntohs(struct.unpack('H', s[6:8])[0] & 0x1f)
    d['ttl'] = s[8]
    d['protocol'] = s[9]
    d['source_address'] = socket.inet_ntoa(s[12:16])
    d['destination_address'] = socket.inet_ntoa(s[16:20])
    if d['header_len'] > 5:
        d['options'] = s[20:4*(d['header_len']-5)]
    else:
        d['options'] = None
    d['data'] = s[4*d['header_len']:]
    return d


def decode_ipv6_packet(s):
    """Decode IPv6 packet"""
    d = {}
    d['version'] = (s[0] & 0xf0) >> 4
    d['nxthdr'] = s[6]
    d['plen'] = struct.unpack("!h", s[4:6])[0]
    d['source_address'] = "[" + socket.inet_ntop(socket.AF_INET6, s[8:24]) + "]"
    d['destination_address'] = "[" + socket.inet_ntop(socket.AF_INET6, s[24:40]) + "]"
    d['protocol'] = s[6]
    d['data'] = s[40:]
    return d


def is_anonymous_ntlm(data):
    """Check if NTLM packet is anonymous"""
    LMhashLen = struct.unpack('<H', data[14:16])[0]
    if LMhashLen == 0 or LMhashLen == 1:
        return False
    else:
        return True
