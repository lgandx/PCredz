"""
HTTP protocol parsers
Handles HTTP Basic Auth, Forms, NTLM, OAuth, JWT, API Keys
"""

import re
import struct
import codecs
from base64 import b64decode
from datetime import datetime

from ..config import HTTP_USERNAME_RE, HTTP_PASSWORD_RE, NTLMSSP2_RE, NTLMSSP3_RE, JWT_RE
from ..utils import is_credential_duplicate, is_anonymous_ntlm


def parse_http_basic(data, src_ip, dst_ip, config):
    """Parse HTTP Basic Authentication"""
    basic64 = re.findall(b'(?<=Authorization: Basic )[^\n]*', data)
    if basic64:
        basic = b''.join(basic64)
        try:
            decoded = b64decode(basic).decode('latin-1')
            message = f'Found HTTP Basic authentication: {decoded}\n'
            
            if not is_credential_duplicate("http_basic", decoded, config['deduplicate']):
                config['text_writer'].write_to_file("logs/HTTP-Basic.txt", message, message)
                
                parts = decoded.split(':', 1)
                username = parts[0] if len(parts) > 0 else 'N/A'
                password = parts[1] if len(parts) > 1 else 'N/A'
                
                cred_dict = {
                    "timestamp": datetime.now().isoformat(),
                    "protocol": "HTTP",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "credential_type": "basic_auth",
                    "username": username,
                    "password": password,
                }
                config['json_writer'].write(cred_dict)
                config['csv_writer'].write(cred_dict["timestamp"], "HTTP", src_ip, 0, dst_ip, 0, "basic_auth", username, password, "Basic Auth")
                
                if config['verbose']:
                    print(f"{src_ip} > {dst_ip}\n{message}")
        except:
            pass


def parse_http_forms(data, src_ip, dst_ip, config):
    """Parse HTTP form-based authentication"""
    http_user = HTTP_USERNAME_RE.search(data)
    http_pass = HTTP_PASSWORD_RE.search(data)
    
    if http_user and http_pass:
        user_match = re.findall(b'(%s=[^&]+)' % http_user.group(0), data, re.IGNORECASE)
        pass_match = re.findall(b'(%s=[^&]+)' % http_pass.group(0), data, re.IGNORECASE)
        
        if user_match and pass_match:
            try:
                message = f'Found possible HTTP authentication {user_match[0].decode("latin-1")}:{pass_match[0].decode("latin-1")}\n'
                
                if not is_credential_duplicate(user_match[0].decode('latin-1'), pass_match[0].decode('latin-1'), config['deduplicate']):
                    config['text_writer'].write_to_file("logs/HTTP-Login-Forms.txt", message, message)
                    
                    if config['verbose']:
                        print(f"{src_ip} > {dst_ip}\n{message}")
            except:
                pass


def parse_ntlm_http(data, src_ip, dst_ip, config):
    """Parse NTLM over HTTP"""
    # HTTP NTLM authentication
    http_ntlm2 = re.findall(b'(?<=WWW-Authenticate: NTLM )[^\\r]*', data)
    http_ntlm3 = re.findall(b'(?<=Authorization: NTLM )[^\\r]*', data)
    
    if http_ntlm2:
        try:
            packet = b64decode(b''.join(http_ntlm2))
            if NTLMSSP2_RE.findall(packet, re.DOTALL):
                challenge = codecs.encode(packet[24:32], 'hex')
                # Store challenge for next packet
                config['_http_ntlm_challenge'] = challenge
        except:
            pass
    
    if http_ntlm3:
        try:
            packet = b64decode(b''.join(http_ntlm3))
            if NTLMSSP3_RE.findall(packet, re.DOTALL):
                if is_anonymous_ntlm(packet):
                    challenge = config.get('_http_ntlm_challenge')
                    if challenge:
                        from .auth_parsers import parse_ntlm_hash
                        result = parse_ntlm_hash(packet, challenge, config)
                        if result and config['verbose']:
                            print(f"{src_ip} > {dst_ip}\n{result[0]}")
        except:
            pass


def parse_oauth_jwt(data, src_ip, dst_ip, config):
    """Extract OAuth tokens and JWT"""
    # OAuth Bearer token
    oauth_match = re.search(b'Authorization:\\s*Bearer\\s+([A-Za-z0-9\\-._~+/]+=*)', data, re.IGNORECASE)
    if oauth_match:
        token = oauth_match.group(1).decode('latin-1')
        message = f'Found OAuth Bearer token: {token[:30]}...\n'
        
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
                print(f"{src_ip} > {dst_ip}\n{message}")
    
    # JWT
    jwt_tokens = JWT_RE.findall(data)
    for jwt in jwt_tokens:
        jwt_str = jwt.decode('latin-1')
        try:
            parts = jwt_str.split('.')
            if len(parts) == 3:
                payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
                payload_decoded = b64decode(payload).decode('utf-8', errors='ignore')
                
                message = f'Found JWT: {jwt_str[:50]}...\nPayload: {payload_decoded[:200]}\n'
                
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
                        print(f"{src_ip} > {dst_ip}\n{message}")
        except:
            pass


def parse_api_keys(data, src_ip, dst_ip, config):
    """Detect API keys in HTTP headers"""
    # X-API-Key header
    api_key_match = re.search(b'X-API-Key:\\s*([A-Za-z0-9\\-_]{20,})', data, re.IGNORECASE)
    if api_key_match:
        api_key = api_key_match.group(1).decode('latin-1')
        message = f'Found API Key (X-API-Key): {api_key}\n'
        
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
                print(f"{src_ip} > {dst_ip}\n{message}")
