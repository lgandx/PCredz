"""
Authentication protocol parsers
Handles NTLM, Kerberos, SNMP
"""

import struct
import codecs
from datetime import datetime

from ..utils import is_anonymous_ntlm


def parse_ntlm_hash(data, challenge, config):
    """Parse NTLM authentication hash"""
    packet_len = len(data)
    if packet_len > 0:
        sspi_start = data[:]
        lmhash_len = struct.unpack('<H', data[14:16])[0]
        lmhash_offset = struct.unpack('<H', data[16:18])[0]
        lmhash = codecs.encode(sspi_start[lmhash_offset:lmhash_offset+lmhash_len], "hex").upper()
        nthash_len = struct.unpack('<H', data[22:24])[0]
        nthash_offset = struct.unpack('<H', data[24:26])[0]
    
    if nthash_len == 24:
        nthash = codecs.encode(sspi_start[nthash_offset:nthash_offset+nthash_len], "hex").upper()
        domain_len = struct.unpack('<H', data[30:32])[0]
        domain_offset = struct.unpack('<H', data[32:34])[0]
        domain = sspi_start[domain_offset:domain_offset+domain_len].replace(b"\x00", b"")
        user_len = struct.unpack('<H', data[38:40])[0]
        user_offset = struct.unpack('<H', data[40:42])[0]
        user = sspi_start[user_offset:user_offset+user_len].replace(b"\x00", b"")
        writehash = '%s::%s:%s:%s:%s' % (user.decode('latin-1'), domain.decode('latin-1'), lmhash.decode('latin-1'), nthash.decode('latin-1'), challenge.decode('latin-1'))
        config['text_writer'].write_to_file("logs/NTLMv1.txt", writehash, user)
        return "NTLMv1 complete hash is: %s\n" % (writehash), user.decode('latin-1') + "::" + domain.decode('latin-1')
    
    if nthash_len > 60:
        nthash = codecs.encode(sspi_start[nthash_offset:nthash_offset+nthash_len], "hex").upper()
        domain_len = struct.unpack('<H', data[30:32])[0]
        domain_offset = struct.unpack('<H', data[32:34])[0]
        domain = sspi_start[domain_offset:domain_offset+domain_len].replace(b"\x00", b"")
        user_len = struct.unpack('<H', data[38:40])[0]
        user_offset = struct.unpack('<H', data[40:42])[0]
        user = sspi_start[user_offset:user_offset+user_len].replace(b"\x00", b"")
        writehash = '%s::%s:%s:%s:%s' % (user.decode('latin-1'), domain.decode('latin-1'), challenge.decode('latin-1'), nthash[:32].decode('latin-1'), nthash[32:].decode('latin-1'))
        config['text_writer'].write_to_file("logs/NTLMv2.txt", writehash, user)
        return "NTLMv2 complete hash is: %s\n" % (writehash), user.decode('latin-1') + "::" + domain.decode('latin-1')
    else:
        return False


def parse_kerberos_tcp(data, config):
    """Parse Kerberos AS-REQ (TCP)"""
    msg_type = data[19:20]
    enc_type = data[41:42]
    message_type = data[30:31]
    if msg_type == b"\x0a" and enc_type == b"\x17" and message_type == b"\x02":
        if data[49:53] == b"\xa2\x36\x04\x34" or data[49:53] == b"\xa2\x35\x04\x33":
            hash_len = struct.unpack('<b', data[50:51])[0]
            if hash_len == 54:
                hash_bytes = data[53:105]
                switch_hash = hash_bytes[16:] + hash_bytes[0:16]
                name_len = struct.unpack('<b', data[153:154])[0]
                name = data[154:154+name_len]
                domain_len = struct.unpack('<b', data[154+name_len+3:154+name_len+4])[0]
                domain = data[154+name_len+4:154+name_len+4+domain_len]
                build_hash = '$krb5pa$23$%s%s%s%s%s' % (name.decode('latin-1'), "$", domain.decode('latin-1'), "$dummy$", codecs.encode(switch_hash, 'hex').decode('latin-1'))
                config['text_writer'].write_to_file("logs/MSKerb.txt", build_hash, name)
                return 'MSKerb hash found: %s\n' % (build_hash), "$krb5pa$23$" + name.decode('latin-1') + "$" + domain.decode('latin-1') + "$dummy$"
    return False


def parse_kerberos_udp(data, config):
    """Parse Kerberos AS-REQ (UDP)"""
    msg_type = data[17:18]
    enc_type = data[39:40]
    if msg_type == b"\x0a" and enc_type == b"\x17":
        if data[40:44] == b"\xa2\x36\x04\x34" or data[40:44] == b"\xa2\x35\x04\x33":
            hash_len = struct.unpack('<b', data[41:42])[0]
            if hash_len == 54:
                hash_bytes = data[44:96]
                switch_hash = hash_bytes[16:] + hash_bytes[0:16]
                name_len = struct.unpack('<b', data[144:145])[0]
                name = data[145:145+name_len]
                domain_len = struct.unpack('<b', data[145+name_len+3:145+name_len+4])[0]
                domain = data[145+name_len+4:145+name_len+4+domain_len]
                build_hash = '$krb5pa$23$%s%s%s%s%s' % (name.decode('latin-1'), "$", domain.decode('latin-1'), "$dummy$", codecs.encode(switch_hash, 'hex').decode('latin-1'))
                config['text_writer'].write_to_file("logs/MSKerb.txt", build_hash, name)
                return 'MSKerb hash found: %s\n' % (build_hash), "$krb5pa$23$" + name.decode('latin-1') + "$" + domain.decode('latin-1') + "$dummy$"
    return False


def parse_snmp(data, config):
    """Parse SNMP community strings"""
    snmp_version = data[4:5]
    if snmp_version == b"\x00":
        str_len = struct.unpack('<b', data[6:7])[0]
        community = data[7:7+str_len].decode('latin-1')
        config['text_writer'].write_to_file("logs/SNMPv1.txt", community, community)
        return f'Found SNMPv1 Community string: {community}\n'
    if data[3:5] == b"\x01\x01":
        str_len = struct.unpack('<b', data[6:7])[0]
        community = data[7:7+str_len].decode('latin-1')
        config['text_writer'].write_to_file("logs/SNMPv2.txt", community, community)
        return f'Found SNMPv2 Community string: {community}\n'
