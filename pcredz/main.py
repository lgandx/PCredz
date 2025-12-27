"""
PCredz Main Entry Point
Modular version with all enhancements integrated
"""

import sys
import os
import logging
import argparse
import time
import subprocess
import threading
from threading import Thread

# Check Python version
if sys.version_info < (3, 0):
    sys.exit("This version only supports python3.\\nTry python3 ./pcredz")

# Try to import pylibpcap
try:
    import pylibpcap as pcap
    from pylibpcap.pcap import rpcap, Sniff
except ImportError:
    print("libpcap not installed.")
    print("Install with: apt install python3-pip && sudo apt-get install libpcap-dev && pip3 install Cython && pip3 install python-libpcap")
    sys.exit(1)

# Import our modules
from .config import VERSION, PROTOCOLS
from .utils import is_credential_duplicate
from .output import TextWriter, JSONWriter, CSVWriter, send_webhook_alert

# Import all parsers
from .parsers import all_parsers


def show_welcome():
    """Display welcome banner"""
    message = f'''Pcredz {VERSION}

Author: Laurent Gaffie <lgaffie@secorizon.com>
Enhancements: Additional protocols, output formats, and features

This script will extract NTLM (HTTP,LDAP,SMB,MSSQL,RPC, etc), Kerberos,
FTP, HTTP Basic, SSH, Telnet, RDP, MySQL, PostgreSQL, Redis, MongoDB,
cloud credentials (AWS/Azure/GCP), and credit card data from a given pcap
file or from a live interface.
'''
    print(message)


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description=f'Pcredz {VERSION}\\nAuthor: Laurent Gaffie',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Input options (mutually exclusive)
    m_group = parser.add_mutually_exclusive_group()
    m_group.add_argument('-f', type=str, dest="fname", default=None,
                        help="Pcap file to parse")
    m_group.add_argument('-d', type=str, dest="dir_path", default=None,
                        help="Pcap directory to parse recursively")
    m_group.add_argument('-i', type=str, dest="interface", default=None,
                        help="Interface for live capture")
    
    # Output options
    parser.add_argument('-o', type=str, dest="output_path",
                       default=os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))+"/",
                       help="Output directory")
    parser.add_argument('--json', action="store_true", dest="json_output",
                       help="Output credentials in JSON format")
    parser.add_argument('--csv', action="store_true", dest="csv_output",
                       help="Output credentials in CSV format")
    
    # Feature options
    parser.add_argument('-c', action="store_false", dest="activate_cc", default=True,
                       help="Deactivate CC number scanning")
    parser.add_argument('-t', action="store_true", dest="timestamp",
                       help="Include timestamp in messages")
    parser.add_argument('-v', action="store_true", dest="verbose",
                       help="More verbose output")
    parser.add_argument('--no-dedup', action="store_false", dest="deduplicate", default=True,
                       help="Disable credential deduplication")
    parser.add_argument('--webhook', type=str, dest="webhook_url",
                       help="Webhook URL for alerts (Slack/Discord/Teams)")
    
    options = parser.parse_args()
    
    # Validate inputs
    if options.fname is None and options.dir_path is None and options.interface is None:
        print('\\n\\033[1m\\033[31m -f or -d or -i mandatory option missing.\\033[0m\\n')
        parser.print_help()
        sys.exit(-1)
    
    return options


def setup_logging(output_path: str):
    """Setup logging configuration"""
    log_file = os.path.join(output_path, "CredentialDump-Session.log")
    logger = logging.getLogger('Credential-Session')
    logger.setLevel(logging.WARNING)
    handler = logging.FileHandler(log_file, 'a')
    logger.addHandler(handler)
    return logger


def is_cooked_pcap(version):
    """Determine PCAP format type"""
    import re
    
    wifi = re.search(b'802.11', version)
    cooked = re.search(b'Linux \\"?cooked\\"?', version)
    tcpdump = re.search(b'Ethernet', version)
    
    if wifi:
        print("Using 802.11 format\\n")
        return 1
    if cooked:
        print("Using Linux Cooked format\\n")
        return 2
    if tcpdump:
        print("Using TCPDump format\\n")
        return 3
    else:
        print("Unknown format, trying TCPDump format\\n")
        return 3


def decode_file(fname, res, config):
    """Decode PCAP file or live capture"""
    from .parsers import packet_handler
    
    if config['interface'] is not None:
        # Live capture
        try:
            message = f"Pcredz live capture started, using: {config['interface']}\\nStarting timestamp ({time.time()}) corresponds to {time.strftime('%x %X')}"
            print(message)
            config['logger'].warning(message)
            
            p = Sniff(config['interface'], count=-1, promisc=1)
            for plen, t, buf in p.capture():
                packet_handler.print_packet_tcpdump(plen, t, buf, config)
                
        except (KeyboardInterrupt, SystemExit):
            print("\\n\\nCTRL-C hit..Cleaning up...")
            threading.Event().set()
    else:
        # PCAP file
        try:
            p = rpcap(fname)
            config['logger'].warning(f'\\n\\nPcredz started, using:{fname} file')
            version = is_cooked_pcap(res)
            
            # Select appropriate packet handler based on format
            if version == 1:
                handler_func = packet_handler.print_packet_80211
            elif version == 2:
                handler_func = packet_handler.print_packet_cooked
            else:
                handler_func = packet_handler.print_packet_tcpdump
            
            # Process packets
            thread = Thread(target=loop_packets, args=(p, handler_func, config))
            thread.daemon = True
            thread.start()
            
            try:
                while thread.is_alive():
                    thread.join(timeout=1)
            except (KeyboardInterrupt, SystemExit):
                print("\\n\\nCTRL-C hit..Cleaning up...")
                threading.Event().set()
                
        except Exception as e:
            print(f"Can't parse {fname}: {e}")
            sys.exit(1)


def loop_packets(pcap_object, func, config):
    """Loop through packets and process them"""
    for x in pcap_object:
        func(x[0], x[1], x[2], config)


def run(config):
    """Main execution loop"""
    try:
        if config['dir_path'] is not None:
            # Process directory
            for root, dirs, files in os.walk(config['dir_path'], topdown=False):
                for capfile in files:
                    filepath = os.path.join(root, capfile)
                    start_time = time.time()
                    print(f"\\nParsing: {filepath}")
                    
                    p = subprocess.Popen(["file", filepath], stdout=subprocess.PIPE)
                    res, err = p.communicate()
                    decode_file(filepath, res, config)
                    
                    seconds = time.time() - start_time
                    filesize = f'File size {os.stat(filepath).st_size/(1024*1024.0):.3g} Mo'
                    
                    if seconds >= 60:
                        minutes = seconds / 60
                        message = f'\\n{filepath} parsed in: {minutes:.3g} minutes ({filesize}).\\n'
                    else:
                        message = f'\\n{filepath} parsed in: {seconds:.3g} seconds ({filesize}).\\n'
                    
                    print(message)
                    config['logger'].warning(message)
        
        if config['fname'] is not None:
            # Process single file
            p = subprocess.Popen(["file", config['fname']], stdout=subprocess.PIPE)
            res, err = p.communicate()
            decode_file(config['fname'], res, config)
            
            seconds = time.time() - config['start_time']
            filesize = f'File size {os.stat(config["fname"]).st_size/(1024*1024.0):.3g} Mo'
            
            if seconds >= 60:
                minutes = seconds / 60
                message = f'\\n{config["fname"]} parsed in: {minutes:.3g} minutes ({filesize}).\\n'
            else:
                message = f'\\n{config["fname"]} parsed in: {seconds:.3g} seconds ({filesize}).\\n'
            
            print(message)
            config['logger'].warning(message)
        
        if config['interface'] is not None:
            # Live capture
            decode_file(config['fname'], '', config)
            
    except Exception as e:
        print(f"Error: {e}")
        raise


def cleanup(config):
    """Cleanup and save final outputs"""
    # Flush JSON
    if config['json_writer']:
        config['json_writer'].flush()
        count = config['json_writer'].get_count()
        if count > 0:
            print(f"\\n[+] Saved {count} credentials to credentials.json")
    
    # Close CSV
    if config['csv_writer']:
        config['csv_writer'].close()
        print("[+] CSV output saved to credentials.csv")


def main():
    """Main entry point"""
    show_welcome()
    options = parse_arguments()
    
    # Fix output path
    output_path = options.output_path
    if not output_path.endswith('/'):
        output_path += '/'
    
    # Setup logging
    logger = setup_logging(output_path)
    
    # Initialize output writers
    text_writer = TextWriter(output_path, enabled=True)
    json_writer = JSONWriter(output_path, enabled=options.json_output)
    csv_writer = CSVWriter(output_path, enabled=options.csv_output)
    
    # Print status messages
    if options.activate_cc:
        print("CC number scanning activated\\n")
    else:
        print("CC number scanning is deactivated\\n")
    
    if options.json_output:
        print(f"JSON output enabled: {output_path}credentials.json\\n")
    
    if options.csv_output:
        print(f"CSV output enabled: {output_path}credentials.csv\\n")
    
    if options.webhook_url:
        print("Webhook alerts enabled\\n")
    
    # Build configuration dictionary
    config = {
        'verbose': options.verbose,
        'fname': options.fname,
        'dir_path': options.dir_path,
        'interface': options.interface,
        'activate_cc': options.activate_cc,
        'timestamp': options.timestamp,
        'start_time': time.time(),
        'output_path': output_path,
        'deduplicate': options.deduplicate,
        'webhook_url': options.webhook_url,
        'logger': logger,
        'text_writer': text_writer,
        'json_writer': json_writer,
        'csv_writer': csv_writer,
    }
    
    # Register cleanup
    import atexit
    atexit.register(cleanup, config)
    
    # Run
    run(config)


if __name__ == '__main__':
    main()
