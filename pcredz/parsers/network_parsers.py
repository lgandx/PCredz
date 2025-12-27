"""
Network protocol parsers
Handles SSH, Telnet, FTP, SMTP, IMAP, POP3
"""

import re
from base64 import b64decode
from datetime import datetime

from ..utils import is_credential_duplicate


def parse_ssh(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse SSH authentication attempts"""
    # SSH banner detection
    if b'SSH-2.0' in data:
        banner_match = re.search(b'SSH-2.0-([^\r\n]+)', data)
        if banner_match and config['verbose']:
            print(f"[SSH] Banner: {banner_match.group(1).decode('latin-1', errors='ignore')}")
    
    # SSH password authentication
    if len(data) > 50:
        try:
            if b'\x32' in data or b'ssh-userauth' in data:
                username_match = re.search(rb'([a-zA-Z0-9_\-\.]{3,32})\x00.*password', data)
                if username_match:
                    username = username_match.group(1).decode('latin-1', errors='ignore')
                    message = f'Found SSH authentication attempt: {username}\n'
                    
                    if not is_credential_duplicate(username, "ssh_attempt", config['deduplicate']):
                        config['text_writer'].write_to_file("logs/SSH-Attempts.txt", message, username)
                        
                        cred_dict = {
                            "timestamp": datetime.now().isoformat(),
                            "protocol": "SSH",
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "credential_type": "auth_attempt",
                            "username": username,
                            "password": "N/A",
                        }
                        config['json_writer'].write(cred_dict)
                        config['csv_writer'].write(cred_dict["timestamp"], "SSH", src_ip, src_port, dst_ip, dst_port, "auth_attempt", username, "N/A", "SSH auth attempt")
                        
                        if config['verbose']:
                            print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}\n{message}")
        except:
            pass


def parse_telnet(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse Telnet plaintext credentials"""
    # Simple approach: look for plain ASCII input after prompts
    # Remove IAC sequences and look for readable text
    cleaned = re.sub(b'\xff[\xf0-\xff].?', b'', data)
    
    # Look for text input (alphanumeric strings)
    text_match = re.search(rb'([a-zA-Z0-9_@.\-]{3,32})(?:\r\n|\n)', cleaned)
    if text_match:
        cred_str = text_match.group(1).decode('latin-1', errors='ignore')
        # Filter out common noise
        if cred_str not in ['login', 'password', 'Password', 'user', 'username']:
            message = f'Telnet: {cred_str}\n'
            
            if not is_credential_duplicate("telnet", cred_str, config['deduplicate']):
                config['text_writer'].write_to_file("logs/Telnet-Plaintext.txt", message, cred_str)
                
                cred_dict = {
                    "timestamp": datetime.now().isoformat(),
                    "protocol": "Telnet",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "credential_type": "plaintext",
                    "username": cred_str,
                    "password": "N/A",
                }
                config['json_writer'].write(cred_dict)
                config['csv_writer'].write(cred_dict["timestamp"], "Telnet", src_ip, src_port, dst_ip, dst_port, "plaintext", cred_str, "N/A", "Telnet input")
                
                if config['verbose']:
                    print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}\n{message}")


def parse_ftp(data, src_ip, dst_ip, config):
    """Parse FTP USER/PASS commands"""
    ftp_user = re.findall(b'(?<=USER )[^\r]*', data)
    ftp_pass = re.findall(b'(?<=PASS )[^\r]*', data)
    
    if ftp_user:
        config['_ftp_user'] =  b''.join(ftp_user)
    
    if ftp_pass:
        try:
            user = config.get('_ftp_user', b'unknown')
            password = b''.join(ftp_pass)
            message = f'FTP User: {user.decode("latin-1")}\nFTP Pass: {password.decode("latin-1")}\n'
            
            config['text_writer'].write_to_file("logs/FTP-Plaintext.txt", message, message)
            
            if 'ftp_user' in config:
                del config['_ftp_user']
            
            if config['verbose']:
                print(f"{src_ip} > {dst_ip}\n{message}")
        except:
            pass


def parse_smtp(data, config):
    """Parse SMTP authentication"""
    # Check for AUTH PLAIN
    if b'AUTH PLAIN' in data:
        auth_match = re.search(rb'AUTH PLAIN ([A-Za-z0-9+/=]+)', data)
        if auth_match:
            try:
                decoded = b64decode(auth_match.group(1))
                # AUTH PLAIN format: \x00username\x00password
                parts = decoded.split(b'\x00')
                if len(parts) >= 3:
                    username = parts[1].decode('latin-1', errors='ignore')
                    password = parts[2].decode('latin-1', errors='ignore')
                    message = f'SMTP AUTH PLAIN: {username}:{password}\n'
                    config['text_writer'].write_to_file("logs/SMTP-Plaintext.txt", message, username)
                    return message
            except:
                pass
    
    # Original SMTP parser
    basic = data[0:len(data)-2]
    op_code = [b'HELO', b'EHLO', b'MAIL', b'RCPT', b'SIZE', b'DATA', b'QUIT', b'VRFY', b'EXPN', b'RSET']
    if data[0:4] not in op_code:
        try:
            basestr = b64decode(basic)
            if len(basestr) > 1:
                if basestr.decode('ascii'):
                    config['text_writer'].write_to_file("logs/SMTP-Plaintext.txt", basestr.decode('latin-1'), basestr.decode('latin-1'))
                    return f'SMTP decoded Base64 string: {basestr.decode("latin-1")}\n'
        except:
            pass


def parse_imap(data, config):
    """Parse IMAP LOGIN commands"""
    imap_auth = re.findall(b'(?<=LOGIN ")[^\r]*', data)
    if imap_auth:
        message = f'Found IMAP login: "{imap_auth[0].decode("latin-1", errors="ignore")}"\n'
        config['text_writer'].write_to_file("logs/IMAP-Plaintext.txt", message, message)
        return message


def parse_pop(data, config):
    """Parse POP3 USER/PASS commands"""
    ftp_user = re.findall(b'(?<=USER )[^\r]*', data)
    ftp_pass = re.findall(b'(?<=PASS )[^\r]*', data)
    
    if ftp_user:
        config['_pop_user'] = b''.join(ftp_user)
    
    if ftp_pass:
        try:
            user = config.get('_pop_user')
            if user:
                password = b''.join(ftp_pass)
                message = f'Found POP credentials {user.decode("latin-1")}:{password.decode("latin-1")}\n'
                config['text_writer'].write_to_file("logs/POP-Plaintext.txt", message, message)
                del config['_pop_user']
                return message
        except:
            pass
