"""
New protocol parsers (SSH, Telnet, MySQL, PostgreSQL, Redis, MongoDB, Cloud, OAuth, API Keys)
"""

import re
import struct
import codecs
from base64 import b64decode
from datetime import datetime

from ..config import *
from ..utils import is_credential_duplicate, analyze_password_strength
from ..output import send_webhook_alert


def parse_ssh(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse SSH authentication attempts"""
    text_writer = config['text_writer']
    json_writer = config['json_writer']
    csv_writer = config['csv_writer']
    logger = config['logger']
    
    # SSH banner detection
    if b'SSH-2.0' in data:
        banner_match = re.search(b'SSH-2.0-([^\\r\\n]+)', data)
        if banner_match and config['verbose']:
            print(f"[SSH] Banner: {banner_match.group(1).decode('latin-1', errors='ignore')}")
    
    # SSH password authentication
    if len(data) > 50:
        try:
            if b'\\x32' in data or b'ssh-userauth' in data:
                username_match = re.search(b'([a-zA-Z0-9_\\-\\.]{3,32})\\x00.*password', data)
                if username_match:
                    username = username_match.group(1).decode('latin-1', errors='ignore')
                    message = f'Found SSH authentication attempt: {username}\\n'
                    
                    if not is_credential_duplicate(username, "ssh_attempt", config['deduplicate']):
                        text_writer.write_to_file("logs/SSH-Attempts.txt", message, username)
                        
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
                        json_writer.write(cred_dict)
                        csv_writer.write(cred_dict["timestamp"], "SSH", src_ip, src_port, dst_ip, dst_port, "auth_attempt", username, "N/A", "SSH auth attempt")
                        
                        if config['verbose']:
                            print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}")
                            print(message)
        except:
            pass


def parse_telnet(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse Telnet plaintext credentials"""
    text_writer = config['text_writer']
    json_writer = config['json_writer']
    csv_writer = config['csv_writer']
    
    # Remove telnet IAC sequences
    cleaned_data = re.sub(b'\\xff[\\xf0-\\xff].?', b'', data)
    
    login_patterns = [b'login:', b'username:', b'user:', b'Password:', b'password:']
    
    for pattern in login_patterns:
        if pattern.lower() in cleaned_data.lower():
            parts = cleaned_data.split(pattern)
            if len(parts) > 1:
                potential_cred = parts[1][:50].strip()
                potential_cred = re.sub(b'[\\x00-\\x1f\\x7f-\\xff]', b'', potential_cred)
                
                if len(potential_cred) >= 3:
                    cred_str = potential_cred.decode('latin-1', errors='ignore')
                    message = f'Found Telnet credential: {cred_str}\\n'
                    
                    if not is_credential_duplicate("telnet", cred_str, config['deduplicate']):
                        text_writer.write_to_file("logs/Telnet-Plaintext.txt", message, cred_str)
                        
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
                        json_writer.write(cred_dict)
                        csv_writer.write(cred_dict["timestamp"], "Telnet", src_ip, src_port, dst_ip, dst_port, "plaintext", cred_str, "N/A", f"After {pattern.decode()}")
                        
                        if config['verbose']:
                            print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}")
                            print(message)


def parse_mysql(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse MySQL authentication packets"""
    if len(data) > 40:
        try:
            if data[4:5] == b'\\x85' or data[4:5] == b'\\x8d':
                offset = 32
                username_end = data.find(b'\\x00', offset)
                if username_end > offset:
                    username = data[offset:username_end].decode('latin-1', errors='ignore')
                    if len(username) > 0 and username.isprintable():
                        message = f'Found MySQL authentication: {username}\\n'
                        
                        if not is_credential_duplicate(username, "mysql_auth", config['deduplicate']):
                            config['text_writer'].write_to_file("logs/MySQL-Auth.txt", message, username)
                            
                            cred_dict = {
                                "timestamp": datetime.now().isoformat(),
                                "protocol": "MySQL",
                                "src_ip": src_ip,
                                "src_port": src_port,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "credential_type": "auth_packet",
                                "username": username,
                                "password": "hashed",
                            }
                            config['json_writer'].write(cred_dict)
                            config['csv_writer'].write(cred_dict["timestamp"], "MySQL", src_ip, src_port, dst_ip, dst_port, "auth_packet", username, "hashed", "Password hashed")
                            
                            if config['verbose']:
                                print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}")
                                print(message)
        except:
            pass


def parse_postgresql(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse PostgreSQL authentication"""
    if len(data) > 20:
        try:
            if data[4:8] == b'\\x00\\x03\\x00\\x00':
                params_data = data[8:]
                params = {}
                offset = 0
                while offset < len(params_data):
                    key_end = params_data.find(b'\\x00', offset)
                    if key_end == -1:
                        break
                    key = params_data[offset:key_end].decode('latin-1', errors='ignore')
                    if key == '':
                        break
                    
                    offset = key_end + 1
                    value_end = params_data.find(b'\\x00', offset)
                    if value_end == -1:
                        break
                    value = params_data[offset:value_end].decode('latin-1', errors='ignore')
                    params[key] = value
                    offset = value_end + 1
                
                if 'user' in params:
                    username = params['user']
                    database = params.get('database', 'N/A')
                    message = f'Found PostgreSQL connection: user={username}, database={database}\\n'
                    
                    if not is_credential_duplicate(username, database, config['deduplicate']):
                        config['text_writer'].write_to_file("logs/PostgreSQL-Auth.txt", message, username)
                        
                        cred_dict = {
                            "timestamp": datetime.now().isoformat(),
                            "protocol": "PostgreSQL",
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port,
                            "credential_type": "connection",
                            "username": username,
                            "password": "N/A",
                        }
                        config['json_writer'].write(cred_dict)
                        config['csv_writer'].write(cred_dict["timestamp"], "PostgreSQL", src_ip, src_port, dst_ip, dst_port, "connection", username, "N/A", f"DB: {database}")
                        
                        if config['verbose']:
                            print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}")
                            print(message)
        except:
            pass


def parse_redis(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse Redis AUTH commands"""
    if b'AUTH' in data:
        auth_match = re.search(b'AUTH\\r\\n\\$([0-9]+)\\r\\n([^\\r]+)', data)
        if auth_match:
            password_len = int(auth_match.group(1))
            password = auth_match.group(2).decode('latin-1', errors='ignore')[:password_len]
            
            message = f'Found Redis AUTH password: {password}\\n'
            
            if not is_credential_duplicate("redis", password, config['deduplicate']):
                config['text_writer'].write_to_file("logs/Redis-Auth.txt", message, password)
                
                strength = analyze_password_strength(password)
                
                cred_dict = {
                    "timestamp": datetime.now().isoformat(),
                    "protocol": "Redis",
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "credential_type": "plaintext",
                    "username": "redis",
                    "password": password,
                    "privileged": True
                }
                config['json_writer'].write(cred_dict)
                config['csv_writer'].write(cred_dict["timestamp"], "Redis", src_ip, src_port, dst_ip, dst_port, "plaintext", "redis", password, f"Strength: {strength['score']}")
                send_webhook_alert(config['webhook_url'], cred_dict, config['verbose'])
                
                if config['verbose']:
                    print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}")
                    print(message)


def parse_mongodb(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse MongoDB authentication"""
    if len(data) > 50:
        if b'saslStart' in data or b'authenticate' in data:
            username_match = re.search(b'n=([^,]+)', data)
            if username_match:
                username = username_match.group(1).decode('latin-1', errors='ignore')
                message = f'Found MongoDB authentication: {username}\\n'
                
                if not is_credential_duplicate(username, "mongodb_auth", config['deduplicate']):
                    config['text_writer'].write_to_file("logs/MongoDB-Auth.txt", message, username)
                    
                    cred_dict = {
                        "timestamp": datetime.now().isoformat(),
                        "protocol": "MongoDB",
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "credential_type": "scram_auth",
                        "username": username,
                        "password": "hashed",
                    }
                    config['json_writer'].write(cred_dict)
                    config['csv_writer'].write(cred_dict["timestamp"], "MongoDB", src_ip, src_port, dst_ip, dst_port, "scram_auth", username, "hashed", "SCRAM auth")
                    
                    if config['verbose']:
                        print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}")
                        print(message)


def parse_cloud_credentials(data, src_ip, dst_ip, config):
    """Detect cloud provider credentials"""
    # AWS Access Key
    aws_keys = AWS_KEY_RE.findall(data)
    for key in aws_keys:
        key_str = key.decode('latin-1')
        message = f'🔐 Found AWS Access Key: {key_str}\\n'
        
        if not is_credential_duplicate("aws", key_str, config['deduplicate']):
            config['text_writer'].write_to_file("logs/Cloud-Credentials.txt", message, key_str)
            
            cred_dict = {
                "timestamp": datetime.now().isoformat(),
                "protocol": "HTTP/HTTPS",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "credential_type": "aws_access_key",
                "username": "N/A",
                "password": key_str,
                "privileged": True
            }
            config['json_writer'].write(cred_dict)
            config['csv_writer'].write(cred_dict["timestamp"], "AWS", src_ip, 0, dst_ip, 0, "access_key", "N/A", key_str, "CRITICAL")
            send_webhook_alert(config['webhook_url'], cred_dict, config['verbose'])
            
            print("\\033[1m\\033[31m" + f"{src_ip} > {dst_ip}" + '\\n' + message + "\\033[0m")
    
    # GitHub Personal Access Token
    github_tokens = GITHUB_TOKEN_RE.findall(data)
    for token in github_tokens:
        token_str = token.decode('latin-1')
        message = f'🔐 Found GitHub Token: {token_str[:20]}...\\n'
        
        if not is_credential_duplicate("github", token_str, config['deduplicate']):
            config['text_writer'].write_to_file("logs/Cloud-Credentials.txt", message, token_str)
            
            cred_dict = {
                "timestamp": datetime.now().isoformat(),
                "protocol": "HTTP/HTTPS",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "credential_type": "github_token",
                "username": "N/A",
                "password": token_str,
                "privileged": True
            }
            config['json_writer'].write(cred_dict)
            config['csv_writer'].write(cred_dict["timestamp"], "GitHub", src_ip, 0, dst_ip, 0, "pat_token", "N/A", token_str, "Personal Access Token")
            send_webhook_alert(config['webhook_url'], cred_dict, config['verbose'])
            
            print("\\033[1m\\033[31m" + f"{src_ip} > {dst_ip}" + '\\n' + message + "\\033[0m")


def parse_oauth_jwt(data, src_ip, dst_ip, config):
    """Extract OAuth tokens and JWT"""
    # OAuth Bearer token
    oauth_match = re.search(b'Authorization:\\s*Bearer\\s+([A-Za-z0-9\\-._~+/]+=*)', data, re.IGNORECASE)
    if oauth_match:
        token = oauth_match.group(1).decode('latin-1')
        message = f'Found OAuth Bearer token: {token[:30]}...\\n'
        
        if not is_credential_duplicate("oauth", token, config['deduplicate']):
            config['text_writer'].write_to_file("logs/OAuth-Tokens.txt", message, token)
            
            cred_dict = {
                "timestamp": datetime.now().isoformat(),
                "protocol": "HTTP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "credential_type": "oauth_bearer",
                "username": "N/A",
                "password": token,
            }
            config['json_writer'].write(cred_dict)
            config['csv_writer'].write(cred_dict["timestamp"], "OAuth", src_ip, 0, dst_ip, 0, "bearer_token", "N/A", token, "OAuth 2.0")
            
            if config['verbose']:
                print(f"{src_ip} > {dst_ip}")
                print(message)
    
    # JWT
    jwt_tokens = JWT_RE.findall(data)
    for jwt in jwt_tokens:
        jwt_str = jwt.decode('latin-1')
        try:
            parts = jwt_str.split('.')
            if len(parts) == 3:
                payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
                payload_decoded = b64decode(payload).decode('utf-8', errors='ignore')
                
                message = f'Found JWT: {jwt_str[:50]}...\\nPayload: {payload_decoded[:200]}\\n'
                
                if not is_credential_duplicate("jwt", jwt_str, config['deduplicate']):
                    config['text_writer'].write_to_file("logs/JWT-Tokens.txt", message, jwt_str)
                    
                    cred_dict = {
                        "timestamp": datetime.now().isoformat(),
                        "protocol": "HTTP",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "credential_type": "jwt",
                        "username": "N/A",
                        "password": jwt_str,
                    }
                    config['json_writer'].write(cred_dict)
                    config['csv_writer'].write(cred_dict["timestamp"], "JWT", src_ip, 0, dst_ip, 0, "jwt_token", "N/A", jwt_str[:50], payload_decoded[:50])
                    
                    if config['verbose']:
                        print(f"{src_ip} > {dst_ip}")
                        print(message)
        except:
            pass


def parse_api_keys(data, src_ip, dst_ip, config):
    """Detect API keys in headers"""
    # X-API-Key header
    api_key_match = re.search(b'X-API-Key:\\s*([A-Za-z0-9\\-_]{20,})', data, re.IGNORECASE)
    if api_key_match:
        api_key = api_key_match.group(1).decode('latin-1')
        message = f'Found API Key (X-API-Key): {api_key}\\n'
        
        if not is_credential_duplicate("apikey", api_key, config['deduplicate']):
            config['text_writer'].write_to_file("logs/API-Keys.txt", message, api_key)
            
            cred_dict = {
                "timestamp": datetime.now().isoformat(),
                "protocol": "HTTP",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "credential_type": "api_key",
                "username": "N/A",
                "password": api_key,
            }
            config['json_writer'].write(cred_dict)
            config['csv_writer'].write(cred_dict["timestamp"], "API", src_ip, 0, dst_ip, 0, "api_key", "N/A", api_key, "X-API-Key")
            
            if config['verbose']:
                print(f"{src_ip} > {dst_ip}")
                print(message)
