#!/usr/bin/env python3
"""
Extract and modularize legacy parsers from original Pcredz
This script reads Pcredz.backup and extracts parser functions
"""

import re
import os

def extract_function(content, func_name):
    """Extract a function from the source code"""
    # Find function definition
    pattern = rf'(def {func_name}\([^)]+\):.*?)(?=\n(?:def |[A-Z]|$))'
    match = re.search(pattern, content, re.DOTALL)
    if match:
        return match.group(1).rstrip()
    return None

def main():
    # Read original file
    with open('Pcredz.backup', 'r') as f:
        content = f.read()
    
    # Extract parser functions
    parsers = [
        'ParseCTX1Hash',
        'ParseNTLMHash',
        'ParseMSKerbv5TCP',
        'ParseMSKerbv5UDP',
        'ParseSNMP',
        'ParseSMTP',
        'ParseSqlClearTxtPwd',
        'ParseMSSQLPlainText',
    ]
    
    # Build legacy_parsers.py
    output = '''"""
Legacy parser functions from original PCredz
Extracted and adapted for modular structure
"""

import struct
import codecs
import logging
from base64 import b64decode
from datetime import datetime

from ..config import *
from ..utils import parse_ctx1_hash, is_anonymous_ntlm
from ..output import send_webhook_alert

'''
    
    # Add extracted functions
    for parser in parsers:
        func_code = extract_function(content, parser)
        if func_code:
            # Adapt function name to snake_case
            snake_name = re.sub(r'(?<!^)(?=[A-Z])', '_', parser).lower()
            output += f"\n\n{func_code}"
            print(f"✓ Extracted {parser}")
        else:
            print(f"✗ Could not extract {parser}")
    
    # Write output
    os.makedirs('pcredz/parsers', exist_ok=True)
    with open('pcredz/parsers/legacy_parsers.py', 'w') as f:
        f.write(output)
    
    print(f"\n✅ Created pcredz/parsers/legacy_parsers.py")

if __name__ == '__main__':
    main()
