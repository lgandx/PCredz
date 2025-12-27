"""Output writers for different formats"""

import os
import json
import csv
import logging
from typing import Dict, Optional, TextIO
from datetime import datetime


class OutputWriter:
    """Base output writer class"""
    
    def __init__(self, output_dir: str, enabled: bool = True):
        self.output_dir = output_dir
        self.enabled = enabled
        self.logger = logging.getLogger('Credential-Session')
        
    def write(self, data: Dict):
        """Write credential data"""
        raise NotImplementedError


class TextWriter(OutputWriter):
    """Traditional text file writer (maintains backward compatibility)"""
    
    def write_to_file(self, filename: str, data: str, user: str):
        """Write data to text file (original WriteData function)"""
        filepath = os.path.join(self.output_dir, filename)
        
        if isinstance(user, str):
            user = user.encode('latin-1')
            
        if not os.path.isfile(filepath):
            if not os.path.isdir(os.path.dirname(filepath)):
                os.makedirs(os.path.dirname(filepath))
            with open(filepath, "w") as outf:
                outf.write(data + '\n')
            return
            
        # Check for duplicates
        with open(filepath, "r") as filestr:
            import codecs
            import re
            if re.search(codecs.encode(user, 'hex'), 
                        codecs.encode(filestr.read().encode('latin-1'), 'hex')):
                return False
                
        with open(filepath, "a") as outf2:
            outf2.write(data + '\n')


class JSONWriter(OutputWriter):
    """JSON output writer"""
    
    def __init__(self, output_dir: str, enabled: bool = True):
        super().__init__(output_dir, enabled)
        self.credentials = []
        self.filepath = os.path.join(output_dir, "credentials.json")
        
    def write(self, cred_dict: Dict):
        """Add credential to JSON array"""
        if not self.enabled:
            return
            
        self.credentials.append(cred_dict)
        
        # Flush every 10 credentials
        if len(self.credentials) % 10 == 0:
            self.flush()
    
    def flush(self):
        """Write all credentials to JSON file"""
        if not self.enabled or not self.credentials:
            return
            
        with open(self.filepath, 'w') as f:
            json.dump(self.credentials, f, indent=2)
    
    def get_count(self) -> int:
        """Get number of credentials collected"""
        return len(self.credentials)


class CSVWriter(OutputWriter):
    """CSV output writer"""
    
    def __init__(self, output_dir: str, enabled: bool = True):
        super().__init__(output_dir, enabled)
        self.filepath = os.path.join(output_dir, "credentials.csv")
        self.file_handle: Optional[TextIO] = None
        self.csv_writer = None
        
        if enabled:
            self._initialize()
    
    def _initialize(self):
        """Initialize CSV file with headers"""
        file_exists = os.path.isfile(self.filepath)
        self.file_handle = open(self.filepath, 'a', newline='')
        self.csv_writer = csv.writer(self.file_handle)
        
        # Write header if new file
        if not file_exists or os.stat(self.filepath).st_size == 0:
            self.csv_writer.writerow([
                'timestamp', 'protocol', 'src_ip', 'src_port', 
                'dst_ip', 'dst_port', 'credential_type', 
                'username', 'password', 'notes'
            ])
    
    def write(self, timestamp, protocol, src_ip, src_port, dst_ip, dst_port,
              cred_type, username, password, notes=""):
        """Write credential to CSV"""
        if not self.enabled or not self.csv_writer:
            return
            
        self.csv_writer.writerow([
            timestamp, protocol, src_ip, src_port,
            dst_ip, dst_port, cred_type, username, password, notes
        ])
        self.file_handle.flush()
    
    def close(self):
        """Close CSV file"""
        if self.file_handle:
            self.file_handle.close()
