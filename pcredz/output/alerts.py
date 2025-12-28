"""Webhook alerting for critical credentials"""

import logging
from typing import Dict, Optional


def send_webhook_alert(webhook_url: Optional[str], credential_dict: Dict, verbose: bool = False):
    """
    Send webhook alert to Slack/Discord/Teams
    
    Args:
        webhook_url: Webhook URL (None to disable)
        credential_dict: Credential data dictionary
        verbose: Print debug messages
    """
    if not webhook_url:
        return
    
    logger = logging.getLogger('Credential-Session')
    
    try:
        import requests
        
        # Determine color based on privilege level
        color = "danger" if credential_dict.get('privileged', False) else "warning"
        
        # Build Slack-compatible payload
        payload = {
            "text": f"[Alert] Credential Captured: {credential_dict.get('username', 'N/A')}",
            "attachments": [{
                "color": color,
                "fields": [
                    {
                        "title": "Protocol",
                        "value": credential_dict.get('protocol', 'Unknown'),
                        "short": True
                    },
                    {
                        "title": "Type",
                        "value": credential_dict.get('credential_type', 'Unknown'),
                        "short": True
                    },
                    {
                        "title": "Username",
                        "value": credential_dict.get('username', 'N/A'),
                        "short": True
                    },
                    {
                        "title": "Source IP",
                        "value": credential_dict.get('src_ip', 'N/A'),
                        "short": True
                    }
                ],
                "footer": "PCredz Network Sniffer",
                "ts": int(credential_dict.get('timestamp_unix', 0)) if 'timestamp_unix' in credential_dict else None
            }]
        }
        
        response = requests.post(webhook_url, json=payload, timeout=5)
        response.raise_for_status()
        
        if verbose:
            print(f"[+] Webhook alert sent successfully")
            
    except ImportError:
        if verbose:
            print("[!] 'requests' module not installed. Install with: pip3 install requests")
    except Exception as e:
        logger.warning(f"Webhook alert failed: {e}")
        if verbose:
            print(f"[!] Webhook alert failed: {e}")
