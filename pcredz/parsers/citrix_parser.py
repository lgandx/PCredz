"""
Citrix CTX1 hash parser
Extracted from original Pcredz
"""

import re


def parse_ctx1_hash(data, config):
    """Parse Citrix CTX1 password hash"""
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
        x = c*16+d
        pc = chr(x^last)
        return pc

    x = re.sub('[^A-P]', '', data.upper())
    decrypted = str(decrypt(x))
    
    message = f'Found Citrix CTX1 password: {decrypted}\n'
    config['text_writer'].write_to_file("logs/CTX1-Plaintext.txt", message, decrypted)
    
    return decrypted
