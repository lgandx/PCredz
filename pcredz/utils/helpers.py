"""Utility functions for PCredz"""

import hashlib
import re
from typing import Dict, Set
from .config import WEAK_PASSWORDS

# Global state for deduplication
credential_hashes: Set[str] = set()


def is_credential_duplicate(username: str, password: str, enabled: bool = True) -> bool:
    """Check if credential is a duplicate using SHA-256 hash"""
    if not enabled:
        return False
    
    cred_hash = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()
    if cred_hash in credential_hashes:
        return True
    credential_hashes.add(cred_hash)
    return False


def analyze_password_strength(password: str) -> Dict:
    """
    Analyze password strength
    Returns: dict with score, is_weak, is_common, length
    """
    score = 0
    if len(password) >= 12:
        score += 25
    if re.search(r'[A-Z]', password):
        score += 25
    if re.search(r'[0-9]', password):
        score += 25
    if re.search(r'[^A-Za-z0-9]', password):
        score += 25
    
    is_common = password.lower() in WEAK_PASSWORDS
    
    return {
        "score": score,
        "is_weak": score < 50,
        "is_common": is_common,
        "length": len(password)
    }


def luhn(n):
    """Luhn algorithm for credit card validation"""
    r = [int(ch) for ch in str(n)][::-1]
    return (sum(r[0::2]) + sum(sum(divmod(d*2, 10)) for d in r[1::2])) % 10 == 0


def parse_ctx1_hash(data):
    """Parse Citrix CTX1 encoded password"""
    def decrypt(ct):
        pt = ''
        last = 0
        for i in range(0, len(ct), 4):
            pc = dec_letter(ct[i:i+4], last)
            pt += pc
            last ^= ord(pc)
        return pt
    
    def dec_letter(ct, last=0):
        c = (ord(ct[2]) - 1) & 0x0f
        d = (ord(ct[3]) - 1) & 0x0f
        x = c * 16 + d
        pc = chr(x ^ last)
        return pc
    
    x = re.sub('[^A-P]', '', data.upper())
    return str(decrypt(x))
