import json
import logging
import logging.handlers
import os
import random
import time
from datetime import datetime, timezone

from dotenv import load_dotenv

from scenarios import brute_force, suspicious_login, command_exec
from utils.ip_pool import get_trusted_ip, get_hostname

load_dotenv()

LOG_DIR = os.getenv("LOG_DIR", "/logs")
LOGS_PER_SECOND = float(os.getenv("LOGS_PER_SECOND", "2"))
ATTACK_RATIO = float(os.getenv("ATTACK_RATIO", "0.3"))
BRUTE_FORCE_BURST = int(os.getenv("BRUTE_FORCE_BURST", "8"))

SAFE_COMMANDS = ["ls -la", "pwd", "whoami", "df -h", "uptime", "id", "echo $PATH"]
SAFE_USERS = ["alice", "bob", "carlos", "diana", "engineer1"]


def normal_auth_event() -> dict:
    ip = get_trusted_ip()
    hostname = get_hostname()
    username = random.choice(SAFE_USERS)
    port = random.randint(49152, 65535)
    now = datetime.now(timezone.utc)
    return {
        "@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "log_type": "auth",
        "source_ip": ip,
        "username": username,
        "action": "ssh_login",
        "status": "success",
        "hostname": hostname,
        "pid": random.randint(10000, 65000),
        "port": port,
        "is_off_hours": False,
        "message": f"Accepted password for {username} from {ip} port {port} ssh2",
        "scenario": "normal",
    }


def normal_command_event() -> dict:
    ip = get_trusted_ip()
    hostname = get_hostname()
    username = random.choice(SAFE_USERS)
    cmd = random.choice(SAFE_COMMANDS)
    now = datetime.now(timezone.utc)
    return {
        "@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "log_type": "command",
        "source_ip": ip,
        "username": username,
        "action": "command_execution",
        "status": "executed",
        "hostname": hostname,
        "pid": random.randint(10000, 65000),
        "command": cmd,
        "message": f"Command executed by {username} on {hostname}: {cmd}",
        "scenario": "normal",
    }


def setup_log_file(log_dir: str) -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, "auth.log")

    logger = logging.getLogger("soc-generator")
    logger.setLevel(logging.DEBUG)

    handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=50 * 1024 * 1024,
        backupCount=3,
    )
    # Raw JSON — no formatting overhead
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)

    # Also print to stdout so `docker logs` works
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter("[generator] %(message)s"))
    logger.addHandler(console)

    return logger


def main():
    logger = setup_log_file(LOG_DIR)
    sleep_interval = 1.0 / LOGS_PER_SECOND

    logging.basicConfig(level=logging.INFO)
    logging.info("SOC Log Generator started — LOG_DIR=%s LOGS_PER_SECOND=%s ATTACK_RATIO=%s",
                 LOG_DIR, LOGS_PER_SECOND, ATTACK_RATIO)

    while True:
        if random.random() < ATTACK_RATIO:
            scenario = random.choices(
                [brute_force, suspicious_login, command_exec],
                weights=[0.5, 0.3, 0.2],
            )[0]

            if scenario is brute_force:
                events = brute_force.generate_burst(BRUTE_FORCE_BURST)
            else:
                events = scenario.generate_burst()
        else:
            if random.random() < 0.7:
                events = [normal_auth_event()]
            else:
                events = [normal_command_event()]

        for event in events:
            logger.info(json.dumps(event, ensure_ascii=False))

        time.sleep(sleep_interval)


if __name__ == "__main__":
    main()
