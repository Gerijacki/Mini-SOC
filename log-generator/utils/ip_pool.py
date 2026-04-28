import random

ATTACKER_IPS = [
    {"ip": "185.220.101.45", "country": "RO", "asn": "AS204608"},
    {"ip": "185.220.101.12", "country": "DE", "asn": "AS204608"},
    {"ip": "91.108.56.23",   "country": "RU", "asn": "AS62014"},
    {"ip": "91.108.4.10",    "country": "RU", "asn": "AS62014"},
    {"ip": "45.142.212.100", "country": "NL", "asn": "AS206728"},
    {"ip": "45.142.212.55",  "country": "NL", "asn": "AS206728"},
    {"ip": "198.54.132.88",  "country": "US", "asn": "AS22552"},
    {"ip": "198.54.132.101", "country": "US", "asn": "AS22552"},
    {"ip": "119.29.10.44",   "country": "CN", "asn": "AS45090"},
    {"ip": "119.29.10.98",   "country": "CN", "asn": "AS45090"},
    {"ip": "5.188.86.172",   "country": "RU", "asn": "AS58271"},
    {"ip": "5.188.86.201",   "country": "RU", "asn": "AS58271"},
    {"ip": "193.32.162.55",  "country": "UA", "asn": "AS47694"},
    {"ip": "193.32.162.12",  "country": "UA", "asn": "AS47694"},
    {"ip": "89.234.157.254", "country": "FR", "asn": "AS4766"},
    {"ip": "89.234.157.40",  "country": "FR", "asn": "AS4766"},
    {"ip": "162.247.74.200", "country": "US", "asn": "AS29216"},
    {"ip": "162.247.74.220", "country": "US", "asn": "AS29216"},
    {"ip": "103.251.167.10", "country": "CN", "asn": "AS132839"},
    {"ip": "103.251.167.88", "country": "CN", "asn": "AS132839"},
]

TRUSTED_IPS = [
    "10.0.1.10",
    "10.0.1.11",
    "10.0.1.20",
    "10.0.1.30",
    "192.168.10.5",
    "192.168.10.10",
    "192.168.10.15",
    "192.168.10.20",
    "172.16.0.5",
    "172.16.0.10",
]

HOSTNAMES = [
    "web-server-01", "web-server-02", "db-server-01",
    "api-server-01", "bastion-01", "mail-server-01",
]


def get_attacker_ip() -> dict:
    return random.choice(ATTACKER_IPS)


def get_trusted_ip() -> str:
    return random.choice(TRUSTED_IPS)


def get_hostname() -> str:
    return random.choice(HOSTNAMES)
