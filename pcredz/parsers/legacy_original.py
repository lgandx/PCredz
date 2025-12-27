"""
Complete extraction of original Pcredz parsers
Properly integrated into modular structure
"""

import re
import struct
import codecs
from base64 import b64decode
from datetime import datetime


def luhn(n):
    """Luhn algorithm for credit card validation"""
    r = [int(ch) for ch in str(n)][::-1]
    return (sum(r[0::2]) + sum(sum(divmod(d*2, 10)) for d in r[1::2])) % 10 == 0


def parse_credit_cards(data, src_ip, dst_ip, config):
    """
    Extract and validate credit card numbers using Luhn algorithm
    Original implementation from Pcredz line 442-666
    """
    if not config.get('activate_cc', True):
        return
    
    # Credit card patterns (Visa, MC, Amex, Discover)
    cc_match_context = re.findall(
        rb'.{30}[^\d][3456][0-9]{3}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[^\d]',
        data, re.DOTALL
    )
    cc_matches = re.findall(
        rb'[^\d][456][0-9]{3}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[^\d]',
        data
    )
    
    if cc_matches:
        for cc in cc_matches:
            try:
                # Remove non-digits
                credit_card = re.sub(rb"\D", b"", cc.strip())
                
                if len(credit_card) <= 16:
                    # Validate with Luhn algorithm
                    if luhn(credit_card.decode('latin-1')):
                        # Get context
                        context = ""
                        if cc_match_context:
                            try:
                                c_match = cc_match_context[0].strip().decode('latin-1', errors='ignore')
                                context = f"Context: {c_match}"
                            except:
                                pass
                        
                        message = f'Possible valid CC (Luhn check OK): {credit_card.decode("latin-1")}\n'
                        if context:
                            message += f'Please verify this match: {context}\n'
                        
                        # Write to log
                        config['text_writer'].write_to_file(
                            "logs/CreditCards.txt",
                            message,
                            credit_card.decode('latin-1')
                        )
                        
                        # JSON/CSV output
                        cred_dict = {
                            "timestamp": datetime.now().isoformat(),
                            "protocol": "HTTP/DATA",
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "credential_type": "credit_card",
                            "username": "N/A",
                            "password": credit_card.decode('latin-1'),
                            "privileged": True
                        }
                        config['json_writer'].write(cred_dict)
                        config['csv_writer'].write(
                            cred_dict["timestamp"], "CreditCard", src_ip, 0, dst_ip, 0,
                            "cc_number", "N/A", credit_card.decode('latin-1'), "Luhn valid"
                        )
                        
                        if config.get('verbose'):
                            print(f"\033[1m\033[31m{src_ip} > {dst_ip}\n{message}\033[0m")
            except Exception as e:
                pass


def parse_http_forms_original(data, src_ip, dst_ip, config):
    """
    HTTP form parsing - original Pcredz implementation
    Lines 415-438 in original
    """
    # Original regex patterns
    HTTP_USERNAME_RE = re.compile(
        b'log|login|wpname|ahd_username|unickname|nickname|user|user_name|alias|pseudo|'
        b'email|username|_username|userid|form_loginname|loginname|login_id|loginid|'
        b'session_key|sessionkey|pop_login|uid|id|user_id|screename|uname|ulogin|'
        b'acctname|account|member|mailaddress|membername|login_username|login_email|'
        b'loginusername|loginemail|uin|sign-in|j_username'
    )
    HTTP_PASSWORD_RE = re.compile(
        b'ahd_password|password|pass|_password|passwd|session_password|sessionpassword|'
        b'login_password|loginpassword|form_pw|pw|userpassword|pwd|upassword|'
        b'login_passwordpasswort|passwrd|wppassword|upasswd|j_password'
    )
    
    http_user = HTTP_USERNAME_RE.search(data)
    http_pass = HTTP_PASSWORD_RE.search(data)
    
    if http_user and http_pass:
        user_match = re.findall(b'(%s=[^&]+)' % http_user.group(0), data, re.IGNORECASE)
        pass_match = re.findall(b'(%s=[^&]+)' % http_pass.group(0), data, re.IGNORECASE)
        
        if user_match and pass_match:
            try:
                message = f'Found possible HTTP authentication {user_match[0].decode("latin-1")}:{pass_match[0].decode("latin-1")}\n'
                
                config['text_writer'].write_to_file(
                    "logs/HTTP-Login-Forms.txt",
                    message,
                    user_match[0].decode('latin-1')
                )
                
                # Parse username and password values
                import urllib.parse
                user_str = user_match[0].decode('latin-1')
                pass_str = pass_match[0].decode('latin-1')
                
                # Extract values after =
                username = urllib.parse.unquote(user_str.split('=', 1)[1] if '=' in user_str else user_str)
                password = urllib.parse.unquote(pass_str.split('=', 1)[1] if '=' in pass_str else pass_str)
                
                cred_dict = {
                    "timestamp": datetime.now().isoformat(),
                    "protocol": "HTTP",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "credential_type": "form_login",
                    "username": username,
                    "password": password,
                }
                config['json_writer'].write(cred_dict)
                config['csv_writer'].write(
                    cred_dict["timestamp"], "HTTP", src_ip, 0, dst_ip, 0,
                    "form_login", username, password, "Form POST"
                )
                
                if config.get('verbose'):
                    print(f"{src_ip} > {dst_ip}\n{message}")
            except Exception as e:
                pass
