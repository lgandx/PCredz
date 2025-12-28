"""
Cloud credential parsers
Handles AWS, Azure, GitHub, and other cloud provider credentials
"""

import re
from datetime import datetime

from ..config import AWS_KEY_RE, GITHUB_TOKEN_RE
from ..utils import is_credential_duplicate
from ..output import send_webhook_alert


def parse_cloud_credentials(data, src_ip, dst_ip, config):
    """Detect cloud provider credentials in traffic"""
    # AWS Access Key
    aws_keys = AWS_KEY_RE.findall(data)
    for key in aws_keys:
        key_str = key.decode('latin-1')
        message = f'[+] Found AWS Access Key: {key_str}\n'
        
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
            
            print("\033[1m\033[31m" + f"{src_ip} > {dst_ip}" + '\n' + message + "\033[0m")
    
    # GitHub Personal Access Token
    github_tokens = GITHUB_TOKEN_RE.findall(data)
    for token in github_tokens:
        token_str = token.decode('latin-1')
        message = f'[+] Found GitHub Token: {token_str[:30]}...\n'
        
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
            
            if config['verbose']:
                print("\033[1m\033[31m" + f"{src_ip} > {dst_ip}" + '\n' + message + "\033[0m")
    
    # Azure connection strings
    if b'AccountKey=' in data or b'SharedAccessSignature=' in data:
        azure_match = re.search(b'(AccountKey|SharedAccessSignature)=([A-Za-z0-9+/=]{20,})', data)
        if azure_match:
            cred_type = azure_match.group(1).decode('latin-1')
            cred_value = azure_match.group(2).decode('latin-1')[:50] + "..."
            
            message = f'[+] Found Azure {cred_type}: {cred_value}\n'
            
            if not is_credential_duplicate("azure", cred_value, config['deduplicate']):
                config['text_writer'].write_to_file("logs/Cloud-Credentials.txt", message, cred_value)
                
                cred_dict = {
                    "timestamp": datetime.now().isoformat(),
                    "protocol": "HTTP/HTTPS",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "credential_type": "azure_key",
                    "username": "N/A",
                    "password": cred_value,
                   "privileged": True
                }
                config['json_writer'].write(cred_dict)
                config['csv_writer'].write(cred_dict["timestamp"], "Azure", src_ip, 0, dst_ip, 0, cred_type, "N/A", cred_value, "CRITICAL")
                send_webhook_alert(config['webhook_url'], cred_dict, config['verbose'])
                
                print("\033[1m\033[31m" + f"{src_ip} > {dst_ip}" + '\n' + message + "\033[0m")
