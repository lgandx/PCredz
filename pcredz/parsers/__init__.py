"""
Parser coordinator - imports and organizes all parser functions
This module ties together all the parsing logic
"""

# Import all parser modules
from . import legacy_parsers  # Original parsers from Pcredz
from . import new_protocols   # New protocol parsers (SSH, Telnet, etc.)
from . import packet_handler  # Packet handling logic

# Re-export for convenience
__all__ = [
    'legacy_parsers',
    'new_protocols', 
    'packet_handler',
    'all_parsers'
]

# Dictionary of all available parsers
all_parsers = {
    # Legacy parsers
    'ntlm': legacy_parsers.parse_ntlm_hash,
    'kerberos_tcp': legacy_parsers.parse_kerberos_tcp,
    'kerberos_udp': legacy_parsers.parse_kerberos_udp,
    'snmp': legacy_parsers.parse_snmp,
    'smtp': legacy_parsers.parse_smtp,
    'mssql': legacy_parsers.parse_mssql_plaintext,
    'ctx1': legacy_parsers.parse_ctx1_hash,
    
    # New protocol parsers
    'ssh': new_protocols.parse_ssh,
    'telnet': new_protocols.parse_telnet,
    'mysql': new_protocols.parse_mysql,
    'postgresql': new_protocols.parse_postgresql,
    'redis': new_protocols.parse_redis,
    'mongodb': new_protocols.parse_mongodb,
    'cloud': new_protocols.parse_cloud_credentials,
    'oauth': new_protocols.parse_oauth_jwt,
    'apikeys': new_protocols.parse_api_keys,
}
