"""
Parser coordinator - imports and organizes all parser functions by protocol type
"""

# Import all parser modules
from . import http_parsers
from . import auth_parsers
from . import database_parsers
from . import network_parsers
from . import cloud_parsers
from . import packet_handler

# Re-export for convenience
__all__ = [
    'http_parsers',
    'auth_parsers',
    'database_parsers',
    'network_parsers',
    'cloud_parsers',
    'packet_handler',
]
