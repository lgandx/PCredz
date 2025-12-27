"""
Credit card detection parser
Extracts credit card numbers from network traffic
"""

import re
from datetime import datetime


def parse_credit_cards(data, src_ip, dst_ip, config):
    """Detect and extract credit card numbers"""
    if not config.get('activate_cc', True):
        return
    
    # Credit card regex patterns (Visa, Mastercard, Amex, Discover)
    # Looking for 13-16 digit numbers with optional spaces/dashes
    cc_match_context = re.findall(rb'.{30}[^\d][3456][0-9]{3}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[^\d]', data, re.DOTALL)
    cc_match = re.findall(rb'[^\d][456][0-9]{3}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[\s-]*[0-9]{4}[^\d]', data)
    
    if cc_match:
        for card in cc_match:
            try:
                # Clean up the card number
                card_str = card.decode('latin-1', errors='ignore').strip()
                # Remove non-digits except spaces and dashes
                card_clean = ''.join(c for c in card_str if c.isdigit() or c in ' -')
                card_clean = card_clean.strip(' -')
                
                # Get context if available
                context = ""
                if cc_match_context:
                    try:
                        context_str = cc_match_context[0].decode('latin-1', errors='ignore')
                        context = f"\nContext: {context_str[:50]}..."
                    except:
                        pass
                
                message = f'Found Credit Card: {card_clean}{context}\n'
                
                # Write to log
                config['text_writer'].write_to_file("logs/CreditCards.txt", message, card_clean)
                
                # JSON/CSV output
                cred_dict = {
                    "timestamp": datetime.now().isoformat(),
                    "protocol": "HTTP/DATA",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "credential_type": "credit_card",
                    "username": "N/A",
                    "password": card_clean,
                    "privileged": True
                }
                config['json_writer'].write(cred_dict)
                config['csv_writer'].write(
                    cred_dict["timestamp"], "CreditCard", src_ip, 0, dst_ip, 0,
                    "cc_number", "N/A", card_clean, "Payment card"
                )
                
                # Alert for credit cards (critical!)
                if config.get('webhook_url'):
                    from .alerts import send_webhook_alert
                    send_webhook_alert(config['webhook_url'], cred_dict, config['verbose'])
                
                if config.get('verbose'):
                    print(f"\033[1m\033[31m{src_ip} > {dst_ip}\n{message}\033[0m")
                    
            except Exception as e:
                pass
