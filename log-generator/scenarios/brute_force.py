import random
from datetime import datetime, timezone, timedelta
from utils.ip_pool import get_attacker_ip, get_hostname

SSH_USERNAMES = ["root", "admin", "ubuntu", "pi", "user", "test", "oracle", "deploy", "git", "postgres"]


def generate_burst(burst_size: int = 8) -> list[dict]:
    attacker = get_attacker_ip()
    ip = attacker["ip"]
    hostname = get_hostname()
    username = random.choice(SSH_USERNAMES)
    pid_base = random.randint(10000, 65000)
    now = datetime.now(timezone.utc)

    events = []
    # Spread failures across a 30-second window, mimicking Hydra/Medusa
    for i in range(burst_size):
        ts = now - timedelta(seconds=random.uniform(0, 30))
        port = random.randint(49152, 65535)
        events.append({
            "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "log_type": "auth",
            "source_ip": ip,
            "source_country": attacker["country"],
            "source_asn": attacker["asn"],
            "username": username,
            "action": "ssh_login",
            "status": "failure",
            "hostname": hostname,
            "pid": pid_base + i,
            "port": port,
            "message": f"Failed password for {username} from {ip} port {port} ssh2",
            "scenario": "brute_force",
        })

    # 15% chance: append a successful login after the brute force (worst case)
    if random.random() < 0.15:
        ts = now - timedelta(seconds=random.uniform(0, 5))
        port = random.randint(49152, 65535)
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
            "pid": pid_base + burst_size,
            "port": port,
            "message": f"Accepted password for {username} from {ip} port {port} ssh2",
            "scenario": "brute_force_success",
        })

    return sorted(events, key=lambda e: e["@timestamp"])
