"""Configuration and constants for PCredz"""

import re

# Version
VERSION = '2.1.0'

# Protocol mappings
PROTOCOLS = {
    6: 'tcp',
    17: 'udp',
    1: 'icmp',
    2: 'igmp',
    3: 'ggp',
    4: 'ipcap',
    5: 'ipstream',
    8: 'egp',
    9: 'igrp',
    29: 'ipv6oipv4',
}

# Pre-compiled regex patterns for performance
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

NTLMSSP1_RE = re.compile(b'NTLMSSP\\x00\\x01\\x00\\x00\\x00.*[^EOF]*')
NTLMSSP2_RE = re.compile(b'NTLMSSP\\x00\\x02\\x00\\x00\\x00.*[^EOF]*', re.DOTALL)
NTLMSSP3_RE = re.compile(b'NTLMSSP\\x00\\x03\\x00\\x00\\x00.*[^EOF]*', re.DOTALL)

# Cloud credential patterns
AWS_KEY_RE = re.compile(b'AKIA[0-9A-Z]{16}')
GITHUB_TOKEN_RE = re.compile(b'ghp_[A-Za-z0-9]{36}')
JWT_RE = re.compile(b'eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+')

# Weak/common passwords
WEAK_PASSWORDS = {
    'password', '123456', 'admin', 'root', 'welcome', 'qwerty', 
    '12345678', '111111', 'password123', 'letmein', 'monkey'
}

# Port mappings
PORT_PROTOCOLS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    80: 'HTTP',
    88: 'Kerberos',
    110: 'POP3',
    143: 'IMAP',
    161: 'SNMP',
    443: 'HTTPS',
    587: 'SMTP',
    1433: 'MSSQL',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    6379: 'Redis',
    27017: 'MongoDB',
}
