"""
Setup script for PCredz
Install with: pip install -e .
Build with: python setup.py build
"""

from setuptools import setup, find_packages
import os

# Read README
def read_file(filename):
    filepath = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return f.read()
    return ''

setup(
    name='pcredz',
    version='2.1.0',
    description='Network credential sniffer - Extract credentials from network traffic',
    long_description=read_file('Readme.md'),
    long_description_content_type='text/markdown',
    author='Laurent Gaffie',
    author_email='lgaffie@secorizon.com',
    url='https://github.com/lgandx/PCredz',
    license='GPLv3',
    
    packages=find_packages(),
    include_package_data=True,
    
    install_requires=[
        'pcapy-ng',
        'requests',
    ],
    
    extras_require={
        'webhooks': ['requests'],
        'dev': ['pytest', 'scapy'],
    },
    
    entry_points={
        'console_scripts': [
            'pcredz=pcredz.main:main',
        ],
    },
    
    python_requires='>=3.6',
    
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Topic :: Security',
        'Topic :: System :: Networking :: Monitoring',
    ],
    
    keywords='security network credentials sniffer pcap ntlm kerberos',
)
