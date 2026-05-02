import random
from datetime import datetime, timezone
from utils.ip_pool import get_attacker_ip, get_hostname

INTERNAL_USERS = ["alice", "bob", "carlos", "diana", "engineer1", "jsmith", "mlopez"]

OFF_HOURS = [0, 1, 2, 3, 4, 22, 23]


def generate_burst() -> list[dict]:
    attacker = get_attacker_ip()
    ip = attacker["ip"]
    hostname = get_hostname()
    username = random.choice(INTERNAL_USERS)
    hour = random.choice(OFF_HOURS)

    now = datetime.now(timezone.utc)
    ts = now.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))
    port = random.randint(49152, 65535)

    event = {
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
        "hour": hour,
        "is_off_hours": True,
        "message": f"Accepted password for {username} from {ip} port {port} ssh2",
        "scenario": "suspicious_login",
    }

    return [event]
