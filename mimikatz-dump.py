#!/usr/bin/env python3
"""
Mimikatz Output Beautifier
Parses and displays Mimikatz output in a clean, NetExec-style format.

================================================================================
OBTAINING MIMIKATZ OUTPUT
================================================================================

All commands require local admin or SYSTEM privileges on the target.

--sam (lsadump::sam)
    Dumps local SAM database - local user NTLM hashes and Kerberos keys.

    Mimikatz commands:
        privilege::debug
        token::elevate
        lsadump::sam

    Output contains: Local users, RIDs, NTLM hashes, AES/DES keys
    Use for: Local account password cracking, pass-the-hash to same local admin
             on other machines (password reuse)

--secrets / --lsa (lsadump::secrets)
    Dumps LSA secrets - DPAPI keys, cached domain creds, service account info.

    Mimikatz commands:
        privilege::debug
        token::elevate
        lsadump::secrets

    Output contains: DPAPI_SYSTEM keys (machine/user), NL$KM, service accounts
    Use for: DPAPI decryption (Chrome passwords, credentials, etc.),
             identifying service accounts running on the box

--lsass / --logonpasswords (sekurlsa::logonpasswords)
    Dumps credentials from LSASS memory - NTLM hashes, cleartext passwords,
    Kerberos tickets.

    Mimikatz commands:
        privilege::debug
        sekurlsa::logonpasswords

    Output contains: NTLM hashes (msv), cleartext passwords (wdigest/kerberos),
                     SSP credentials, Kerberos TGT/TGS tickets
    Use for: Pass-the-hash, pass-the-ticket, lateral movement,
             domain privilege escalation

    Note: wdigest cleartext only available if UseLogonCredential registry key
          is set or on older systems (pre-2012 R2 by default)

--dpapi (sekurlsa::dpapi)
    Dumps DPAPI master keys from LSASS memory.

    Mimikatz commands:
        privilege::debug
        sekurlsa::dpapi

    Output contains: DPAPI master key GUIDs, timestamps, decrypted master keys
    Use for: Offline decryption of DPAPI-protected data (credentials, Chrome
             passwords, certificates, etc.) without needing user password

================================================================================
QUICK REFERENCE - FULL DUMP SEQUENCE
================================================================================

    mimikatz # privilege::debug
    mimikatz # token::elevate
    mimikatz # lsadump::sam
    mimikatz # lsadump::secrets
    mimikatz # sekurlsa::logonpasswords
    mimikatz # sekurlsa::dpapi

Save each output to separate files, or save the entire session and split later.

================================================================================
USAGE EXAMPLES
================================================================================

    # Parse individual files
    python3 mimikatz-dump.py --sam sam.txt
    python3 mimikatz-dump.py --lsass logonpasswords.txt

    # Parse multiple files
    python3 mimikatz-dump.py --sam sam.txt --secrets secrets.txt --lsass lsass.txt

    # Include copy-paste summary
    python3 mimikatz-dump.py --sam sam.txt --lsass lsass.txt --summary

    # Disable colors (for piping to file)
    python3 mimikatz-dump.py --sam sam.txt --no-color > output.txt

================================================================================
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from typing import Optional


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"

    # NetExec-style colors
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    GRAY = "\033[90m"


class Symbols:
    STAR = "[*]"
    PLUS = "[+]"
    MINUS = "[-]"
    INFO = "[i]"


def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"


def print_header(module: str, title: str):
    """Print a section header in NetExec style."""
    mod = colorize(module.ljust(10), Colors.CYAN)
    star = colorize(Symbols.STAR, Colors.BLUE)
    print(f"{mod} {star} {title}")


def print_success(module: str, message: str):
    """Print a success message."""
    mod = colorize(module.ljust(10), Colors.CYAN)
    plus = colorize(Symbols.PLUS, Colors.GREEN)
    print(f"{mod} {plus} {message}")


def print_info(module: str, message: str):
    """Print an info message."""
    mod = colorize(module.ljust(10), Colors.CYAN)
    star = colorize(Symbols.STAR, Colors.BLUE)
    print(f"{mod} {star} {message}")


def print_credential(module: str, cred: str, highlight: bool = False):
    """Print a credential line."""
    mod = colorize(module.ljust(10), Colors.CYAN)
    if highlight:
        print(f"{mod} {colorize(cred, Colors.GREEN)}")
    else:
        print(f"{mod} {cred}")


def print_warning(module: str, message: str):
    """Print a warning message."""
    mod = colorize(module.ljust(10), Colors.CYAN)
    minus = colorize(Symbols.MINUS, Colors.YELLOW)
    print(f"{mod} {minus} {message}")


# =============================================================================
# SAM Parser (lsadump::sam)
# =============================================================================

@dataclass
class SAMUser:
    rid: str = ""
    username: str = ""
    ntlm_hash: str = ""
    aes256: str = ""
    aes128: str = ""
    des_cbc_md5: str = ""


def parse_sam(content: str) -> tuple[dict, list[SAMUser]]:
    """Parse lsadump::sam output."""
    info = {}
    users = []
    current_user = None
    in_credentials = False
    in_old_credentials = False

    lines = content.split('\n')

    for line in lines:
        line = line.rstrip()

        # Parse domain info
        if line.startswith('Domain :'):
            info['domain'] = line.split(':', 1)[1].strip()
        elif line.startswith('SysKey :'):
            info['syskey'] = line.split(':', 1)[1].strip()
        elif line.startswith('Local SID :'):
            info['local_sid'] = line.split(':', 1)[1].strip()
        elif line.startswith('SAMKey :'):
            info['samkey'] = line.split(':', 1)[1].strip()

        # Parse RID and User
        elif line.startswith('RID  :'):
            if current_user and current_user.username:
                users.append(current_user)
            current_user = SAMUser()
            match = re.search(r'RID\s+:\s+(\S+)', line)
            if match:
                current_user.rid = match.group(1)
            in_credentials = False
            in_old_credentials = False

        elif line.startswith('User :'):
            if current_user:
                current_user.username = line.split(':', 1)[1].strip()

        elif 'Hash NTLM:' in line:
            if current_user:
                match = re.search(r'Hash NTLM:\s*(\S+)', line)
                if match:
                    current_user.ntlm_hash = match.group(1)

        # Track credential sections
        elif 'Credentials' in line and 'Old' not in line and 'Supplemental' not in line:
            in_credentials = True
            in_old_credentials = False
        elif 'OldCredentials' in line:
            in_credentials = False
            in_old_credentials = True

        # Parse Kerberos keys (only current, not old)
        elif in_credentials and not in_old_credentials and current_user:
            if 'aes256_hmac' in line:
                match = re.search(r':\s*(\S+)$', line)
                if match:
                    current_user.aes256 = match.group(1)
            elif 'aes128_hmac' in line:
                match = re.search(r':\s*(\S+)$', line)
                if match:
                    current_user.aes128 = match.group(1)
            elif 'des_cbc_md5' in line:
                match = re.search(r':\s*(\S+)$', line)
                if match:
                    current_user.des_cbc_md5 = match.group(1)

    # Don't forget the last user
    if current_user and current_user.username:
        users.append(current_user)

    return info, users


def display_sam(content: str):
    """Display SAM dump in NetExec style."""
    info, users = parse_sam(content)
    module = "SAM"

    print()
    domain = info.get('domain', 'UNKNOWN')
    print_header(module, f"Domain: {colorize(domain, Colors.YELLOW)}")

    if info.get('syskey'):
        print_info(module, f"SysKey: {info['syskey']}")
    if info.get('local_sid'):
        print_info(module, f"Local SID: {info['local_sid']}")

    print_header(module, "Dumping SAM hashes")

    hash_count = 0
    for user in users:
        if user.ntlm_hash:
            # Format: user:rid:LM:NTLM:::
            lm_hash = "aad3b435b51404eeaad3b435b51404ee"
            rid_dec = int(user.rid.split()[0], 16) if user.rid else 0
            hash_line = f"{domain}\\{colorize(user.username, Colors.YELLOW)}:{rid_dec}:{lm_hash}:{colorize(user.ntlm_hash, Colors.GREEN)}:::"
            print_credential(module, hash_line)
            hash_count += 1
        else:
            # User with no hash
            rid_dec = int(user.rid.split()[0], 16) if user.rid else 0
            print_credential(module, f"{domain}\\{colorize(user.username, Colors.GRAY)}:{rid_dec}:(no hash)")

    # Print Kerberos keys for users that have them
    users_with_keys = [u for u in users if u.aes256 or u.aes128]
    if users_with_keys:
        print()
        print_header(module, "Kerberos Keys")
        for user in users_with_keys:
            if user.aes256:
                print_credential(module, f"{domain}\\{user.username}:{colorize('aes256-cts-hmac-sha1-96', Colors.CYAN)}:{user.aes256}")
            if user.aes128:
                print_credential(module, f"{domain}\\{user.username}:{colorize('aes128-cts-hmac-sha1-96', Colors.CYAN)}:{user.aes128}")
            if user.des_cbc_md5:
                print_credential(module, f"{domain}\\{user.username}:{colorize('des-cbc-md5', Colors.CYAN)}:{user.des_cbc_md5}")

    print()
    print_success(module, f"Dumped {colorize(str(hash_count), Colors.GREEN)} SAM hashes")


# =============================================================================
# Secrets Parser (lsadump::secrets)
# =============================================================================

@dataclass
class Secret:
    name: str = ""
    service_info: str = ""
    cur_hex: str = ""
    old_hex: str = ""
    dpapi_machine_cur: str = ""
    dpapi_user_cur: str = ""
    dpapi_machine_old: str = ""
    dpapi_user_old: str = ""


def parse_secrets(content: str) -> tuple[dict, list[Secret]]:
    """Parse lsadump::secrets output."""
    info = {}
    secrets = []
    current_secret = None
    in_cur = False
    in_old = False

    lines = content.split('\n')

    for line in lines:
        line = line.rstrip()

        # Parse domain info
        if line.startswith('Domain :'):
            info['domain'] = line.split(':', 1)[1].strip()
        elif line.startswith('SysKey :'):
            info['syskey'] = line.split(':', 1)[1].strip()
        elif line.startswith('Local name :'):
            match = re.search(r'Local name\s*:\s*(\S+)', line)
            if match:
                info['local_name'] = match.group(1)
        elif line.startswith('Domain name :'):
            info['domain_name'] = line.split(':', 1)[1].strip()

        # Parse secrets
        elif line.startswith('Secret  :'):
            if current_secret and current_secret.name:
                secrets.append(current_secret)
            current_secret = Secret()
            rest = line.split(':', 1)[1].strip()
            # Check for service info
            if '/' in rest and 'service' in rest:
                parts = rest.split('/')
                current_secret.name = parts[0].strip()
                current_secret.service_info = rest
            else:
                current_secret.name = rest
            in_cur = False
            in_old = False

        elif current_secret:
            if line.strip().startswith('cur/hex :'):
                in_cur = True
                in_old = False
            elif line.strip().startswith('old/hex :'):
                in_cur = False
                in_old = True
            elif line.strip().startswith('full:'):
                hex_val = line.split(':', 1)[1].strip()
                if in_cur:
                    current_secret.cur_hex = hex_val
                elif in_old:
                    current_secret.old_hex = hex_val
            elif line.strip().startswith('m/u :'):
                # DPAPI master/user keys
                match = re.search(r'm/u\s*:\s*(\S+)\s*/\s*(\S+)', line)
                if match:
                    if in_cur:
                        current_secret.dpapi_machine_cur = match.group(1)
                        current_secret.dpapi_user_cur = match.group(2)
                    elif in_old:
                        current_secret.dpapi_machine_old = match.group(1)
                        current_secret.dpapi_user_old = match.group(2)

    # Don't forget the last secret
    if current_secret and current_secret.name:
        secrets.append(current_secret)

    return info, secrets


def display_secrets(content: str):
    """Display LSA secrets in NetExec style."""
    info, secrets = parse_secrets(content)
    module = "LSA"

    print()
    domain = info.get('domain', 'UNKNOWN')
    local_name = info.get('local_name', 'UNKNOWN')
    print_header(module, f"Domain: {colorize(domain, Colors.YELLOW)} | Local: {colorize(local_name, Colors.YELLOW)}")

    print_header(module, "Dumping LSA secrets")

    secret_count = 0
    for secret in secrets:
        if secret.name == 'DPAPI_SYSTEM' and secret.dpapi_machine_cur:
            print_credential(module, f"dpapi_machinekey:{colorize('0x' + secret.dpapi_machine_cur, Colors.GREEN)}")
            print_credential(module, f"dpapi_userkey:{colorize('0x' + secret.dpapi_user_cur, Colors.GREEN)}")
            secret_count += 2
        elif secret.name == 'NL$KM':
            if secret.cur_hex:
                print_credential(module, f"NL$KM:{colorize(secret.cur_hex[:64] + '...', Colors.CYAN)}")
                secret_count += 1
        elif secret.service_info:
            # Service account secret
            print_credential(module, f"{colorize(secret.service_info, Colors.YELLOW)}")
            secret_count += 1
        elif secret.cur_hex:
            print_credential(module, f"{secret.name}:{colorize(secret.cur_hex, Colors.GREEN)}")
            secret_count += 1

    print()
    print_success(module, f"Dumped {colorize(str(secret_count), Colors.GREEN)} LSA secrets")


# =============================================================================
# LSASS Parser (sekurlsa::logonpasswords)
# =============================================================================

@dataclass
class KerberosTicket:
    service_name: str = ""
    target_name: str = ""
    client_name: str = ""
    flags: str = ""
    start_time: str = ""
    end_time: str = ""
    ticket_type: str = ""  # TGT or TGS


@dataclass
class LogonSession:
    auth_id: str = ""
    session_type: str = ""
    username: str = ""
    domain: str = ""
    logon_server: str = ""
    logon_time: str = ""
    sid: str = ""
    ntlm: str = ""
    sha1: str = ""
    password: str = ""
    wdigest_user: str = ""
    wdigest_domain: str = ""
    wdigest_password: str = ""
    kerberos_user: str = ""
    kerberos_domain: str = ""
    kerberos_password: str = ""
    kerberos_tickets: list = field(default_factory=list)
    ssp_creds: list = field(default_factory=list)


def parse_lsass(content: str) -> list[LogonSession]:
    """Parse sekurlsa::logonpasswords output."""
    sessions = []
    current_session = None
    current_provider = None
    current_ssp_entry = {}
    current_ticket = None
    current_ticket_group = ""

    lines = content.split('\n')

    for line in lines:
        raw_line = line.rstrip()
        stripped = raw_line.strip()

        # New authentication session
        if 'Authentication Id :' in raw_line:
            if current_session and current_session.username:
                sessions.append(current_session)
            current_session = LogonSession()
            match = re.search(r'Authentication Id\s*:\s*(\S+\s*;\s*\S+)', raw_line)
            if match:
                current_session.auth_id = match.group(1)
            current_provider = None
            current_ticket = None

        elif current_session:
            # Session metadata (handle leading whitespace)
            if stripped.startswith('Session'):
                current_session.session_type = stripped.split(':', 1)[1].strip() if ':' in stripped else ""
            elif stripped.startswith('User Name'):
                current_session.username = stripped.split(':', 1)[1].strip() if ':' in stripped else ""
            elif re.match(r'^Domain\s+:', stripped):
                # Match "Domain            :" at start of line (session metadata)
                current_session.domain = stripped.split(':', 1)[1].strip() if ':' in stripped else ""
            elif stripped.startswith('Logon Server'):
                current_session.logon_server = stripped.split(':', 1)[1].strip() if ':' in stripped else ""
            elif stripped.startswith('Logon Time'):
                current_session.logon_time = stripped.split(':', 1)[1].strip() if ':' in stripped else ""
            elif stripped.startswith('SID') and not stripped.startswith('SID :'):
                if ':' in stripped:
                    current_session.sid = stripped.split(':', 1)[1].strip()

            # Provider detection
            elif stripped == 'msv :':
                current_provider = 'msv'
            elif stripped == 'wdigest :':
                current_provider = 'wdigest'
            elif stripped == 'kerberos :':
                current_provider = 'kerberos'
                current_ticket = None
            elif stripped == 'ssp :':
                current_provider = 'ssp'
            elif stripped in ['tspkg :', 'credman :', 'cloudap :']:
                current_provider = None

            # Parse credentials based on provider
            elif current_provider == 'msv':
                if '* NTLM' in stripped:
                    match = re.search(r'\*\s*NTLM\s*:\s*(\S+)', stripped)
                    if match:
                        current_session.ntlm = match.group(1)
                elif '* SHA1' in stripped:
                    match = re.search(r'\*\s*SHA1\s*:\s*(\S+)', stripped)
                    if match:
                        current_session.sha1 = match.group(1)

            elif current_provider == 'wdigest':
                if '* Username' in stripped:
                    current_session.wdigest_user = stripped.split(':')[-1].strip()
                elif '* Domain' in stripped:
                    current_session.wdigest_domain = stripped.split(':')[-1].strip()
                elif '* Password' in stripped:
                    pwd = stripped.split(':', 1)[-1].strip()
                    if pwd and pwd != '(null)':
                        current_session.wdigest_password = pwd

            elif current_provider == 'kerberos':
                # Kerberos credentials
                if '* Username' in stripped:
                    current_session.kerberos_user = stripped.split(':')[-1].strip()
                elif '* Domain' in stripped:
                    current_session.kerberos_domain = stripped.split(':')[-1].strip()
                elif '* Password' in stripped:
                    pwd = stripped.split(':', 1)[-1].strip()
                    if pwd and pwd != '(null)':
                        current_session.kerberos_password = pwd

                # Kerberos tickets detection
                elif 'Group 0 - Ticket Granting Ticket' in stripped:
                    current_ticket_group = 'TGT'
                elif 'Group 1 - Client Ticket' in stripped or 'Group 2 - Ticket Granting Service' in stripped:
                    current_ticket_group = 'TGS'
                elif stripped.startswith('[') and re.match(r'\[\d+\]', stripped):
                    # New ticket entry
                    if current_ticket and current_ticket.service_name:
                        current_session.kerberos_tickets.append(current_ticket)
                    current_ticket = KerberosTicket()
                    current_ticket.ticket_type = current_ticket_group
                elif current_ticket:
                    if 'Start/End/MaxRenew:' in stripped:
                        match = re.search(r'Start/End/MaxRenew:\s*(.+?)\s*;\s*(.+?)\s*;', stripped)
                        if match:
                            current_ticket.start_time = match.group(1)
                            current_ticket.end_time = match.group(2)
                    elif 'Service Name' in stripped:
                        match = re.search(r'Service Name.*?:\s*(.+)', stripped)
                        if match:
                            current_ticket.service_name = match.group(1).split(';')[0].strip()
                    elif 'Target Name' in stripped:
                        match = re.search(r'Target Name.*?:\s*(.+)', stripped)
                        if match:
                            current_ticket.target_name = match.group(1).split(';')[0].strip()
                    elif 'Client Name' in stripped:
                        match = re.search(r'Client Name.*?:\s*(.+)', stripped)
                        if match:
                            current_ticket.client_name = match.group(1).strip()
                    elif 'Flags' in stripped:
                        match = re.search(r'Flags\s+(\S+)', stripped)
                        if match:
                            current_ticket.flags = match.group(1)

            elif current_provider == 'ssp':
                if re.match(r'\[\d+\]', stripped):
                    current_ssp_entry = {}
                elif '* Username' in stripped:
                    current_ssp_entry['username'] = stripped.split(':')[-1].strip()
                elif '* Domain' in stripped:
                    current_ssp_entry['domain'] = stripped.split(':')[-1].strip()
                elif '* Password' in stripped:
                    pwd = stripped.split(':', 1)[-1].strip()
                    if pwd and pwd != '(null)':
                        current_ssp_entry['password'] = pwd
                        current_session.ssp_creds.append(current_ssp_entry.copy())
                        current_ssp_entry = {}

    # Don't forget the last session and ticket
    if current_session:
        if current_ticket and current_ticket.service_name:
            current_session.kerberos_tickets.append(current_ticket)
        if current_session.username:
            sessions.append(current_session)

    return sessions


def display_lsass(content: str):
    """Display LSASS dump in NetExec style."""
    sessions = parse_lsass(content)
    module = "LSASS"

    print()
    print_header(module, "Parsing logonpasswords output")

    # Collect unique credentials
    creds_seen = set()
    cred_count = 0

    # First pass: collect NTLM hashes
    print_header(module, "NTLM Hashes")
    for session in sessions:
        if session.ntlm and session.username and session.username != '(null)':
            key = f"{session.domain}\\{session.username}:{session.ntlm}"
            if key not in creds_seen:
                creds_seen.add(key)
                domain_user = f"{colorize(session.domain, Colors.YELLOW)}\\{colorize(session.username, Colors.WHITE)}"
                print_credential(module, f"{domain_user} {colorize(session.ntlm, Colors.GREEN)}")
                cred_count += 1

    # Second pass: collect cleartext passwords
    passwords_found = []
    for session in sessions:
        if session.wdigest_password:
            key = f"{session.domain}\\{session.username}:wdigest:{session.wdigest_password}"
            if key not in creds_seen:
                creds_seen.add(key)
                passwords_found.append((session.domain, session.username, 'wdigest', session.wdigest_password))

        if session.kerberos_password:
            key = f"{session.domain}\\{session.username}:kerberos:{session.kerberos_password}"
            if key not in creds_seen:
                creds_seen.add(key)
                passwords_found.append((session.domain, session.username, 'kerberos', session.kerberos_password))

        for ssp in session.ssp_creds:
            if ssp.get('password'):
                domain = ssp.get('domain', session.domain) or '(null)'
                user = ssp.get('username', '')
                key = f"{domain}\\{user}:ssp:{ssp['password']}"
                if key not in creds_seen:
                    creds_seen.add(key)
                    passwords_found.append((domain, user, 'ssp', ssp['password']))

    if passwords_found:
        print()
        print_header(module, f"{colorize('Cleartext Passwords', Colors.RED + Colors.BOLD)}")
        for domain, user, ptype, password in passwords_found:
            domain_user = f"{colorize(domain, Colors.YELLOW)}\\{colorize(user, Colors.WHITE)}"
            ptype_colored = colorize(f"[{ptype}]", Colors.MAGENTA)
            print_credential(module, f"{domain_user} {ptype_colored} {colorize(password, Colors.RED)}")
            cred_count += 1

    # Third pass: collect Kerberos tickets
    all_tickets = []
    for session in sessions:
        for ticket in session.kerberos_tickets:
            all_tickets.append((session.domain, session.username, ticket))

    if all_tickets:
        print()
        print_header(module, f"{colorize('Kerberos Tickets', Colors.CYAN + Colors.BOLD)}")
        for domain, user, ticket in all_tickets:
            domain_user = f"{colorize(domain, Colors.YELLOW)}\\{colorize(user, Colors.WHITE)}"
            ticket_type = colorize(f"[{ticket.ticket_type}]", Colors.MAGENTA)
            service = colorize(ticket.service_name, Colors.GREEN)
            print_credential(module, f"{domain_user} {ticket_type} {service}")
            if ticket.client_name:
                print_credential(module, f"    Client: {ticket.client_name}")
            if ticket.end_time:
                print_credential(module, f"    Expires: {ticket.end_time}")
        print_success(module, f"Found {colorize(str(len(all_tickets)), Colors.GREEN)} Kerberos tickets")

    print()
    print_success(module, f"Found {colorize(str(cred_count), Colors.GREEN)} unique credentials")


# =============================================================================
# DPAPI Parser (sekurlsa::dpapi)
# =============================================================================

@dataclass
class DPAPIKey:
    guid: str = ""
    time: str = ""
    masterkey: str = ""
    sha1: str = ""
    username: str = ""
    domain: str = ""


def parse_dpapi(content: str) -> list[DPAPIKey]:
    """Parse sekurlsa::dpapi output."""
    keys = []
    current_key = None
    current_user = ""
    current_domain = ""

    lines = content.split('\n')

    for line in lines:
        line = line.rstrip()

        # Track current user context
        if line.startswith('User Name'):
            current_user = line.split(':', 1)[1].strip() if ':' in line else ""
        elif line.startswith('Domain'):
            current_domain = line.split(':', 1)[1].strip() if ':' in line else ""

        # Parse DPAPI key entries
        if '* GUID' in line:
            if current_key and current_key.masterkey:
                keys.append(current_key)
            current_key = DPAPIKey()
            current_key.username = current_user
            current_key.domain = current_domain
            match = re.search(r'\{([^}]+)\}', line)
            if match:
                current_key.guid = match.group(1)

        elif current_key:
            if '* Time' in line:
                current_key.time = line.split(':', 1)[1].strip() if ':' in line else ""
            elif '* MasterKey' in line:
                current_key.masterkey = line.split(':', 1)[1].strip() if ':' in line else ""
            elif '* sha1(key)' in line:
                current_key.sha1 = line.split(':', 1)[1].strip() if ':' in line else ""

    # Don't forget the last key
    if current_key and current_key.masterkey:
        keys.append(current_key)

    return keys


def display_dpapi(content: str):
    """Display DPAPI keys in NetExec style."""
    keys = parse_dpapi(content)
    module = "DPAPI"

    print()
    print_header(module, "Parsing DPAPI master keys")

    if not keys:
        print_warning(module, "No DPAPI master keys found")
        return

    # Group by user
    users_keys = {}
    for key in keys:
        user_key = f"{key.domain}\\{key.username}"
        if user_key not in users_keys:
            users_keys[user_key] = []
        users_keys[user_key].append(key)

    for user, user_keys in users_keys.items():
        print()
        print_header(module, f"Keys for {colorize(user, Colors.YELLOW)}")
        for key in user_keys:
            guid_str = colorize(f"{{{key.guid}}}", Colors.CYAN)
            print_credential(module, f"GUID: {guid_str}")
            print_credential(module, f"  Time: {key.time}")
            # Truncate masterkey for display
            mk_display = key.masterkey[:64] + "..." if len(key.masterkey) > 64 else key.masterkey
            print_credential(module, f"  MasterKey: {colorize(mk_display, Colors.GREEN)}")
            if key.sha1:
                print_credential(module, f"  SHA1: {colorize(key.sha1, Colors.MAGENTA)}")

    print()
    print_success(module, f"Found {colorize(str(len(keys)), Colors.GREEN)} DPAPI master keys")


# =============================================================================
# Summary Output
# =============================================================================

def display_summary(sam_content: Optional[str], secrets_content: Optional[str],
                   lsass_content: Optional[str], dpapi_content: Optional[str]):
    """Display a quick summary of all credentials found."""
    module = "SUMMARY"

    print()
    print("=" * 70)
    print_header(module, colorize("Quick Reference - Copy/Paste Ready", Colors.BOLD))
    print("=" * 70)

    all_hashes = []
    all_passwords = []
    seen_hashes = set()

    # Extract from SAM
    if sam_content:
        info, users = parse_sam(sam_content)
        domain = info.get('domain', 'UNKNOWN')
        for user in users:
            if user.ntlm_hash:
                key = f"{domain}\\{user.username}:{user.ntlm_hash}"
                if key not in seen_hashes:
                    seen_hashes.add(key)
                    all_hashes.append(key)

    # Extract from LSASS
    if lsass_content:
        sessions = parse_lsass(lsass_content)
        for session in sessions:
            if session.ntlm and session.username and session.username != '(null)':
                key = f"{session.domain}\\{session.username}:{session.ntlm}"
                if key not in seen_hashes:
                    seen_hashes.add(key)
                    all_hashes.append(key)

            if session.wdigest_password:
                pwd = f"{session.domain}\\{session.username}:{session.wdigest_password}"
                if pwd not in all_passwords:
                    all_passwords.append(pwd)

            if session.kerberos_password:
                pwd = f"{session.domain}\\{session.username}:{session.kerberos_password}"
                if pwd not in all_passwords:
                    all_passwords.append(pwd)

            for ssp in session.ssp_creds:
                if ssp.get('password'):
                    domain = ssp.get('domain', session.domain) or '(null)'
                    user = ssp.get('username', '')
                    pwd = f"{domain}\\{user}:{ssp['password']}"
                    if pwd not in all_passwords:
                        all_passwords.append(pwd)

    if all_hashes:
        print()
        print_header(module, "NTLM Hashes (user:hash)")
        for h in all_hashes:
            print(f"  {h}")

    if all_passwords:
        print()
        print_header(module, f"{colorize('Cleartext Passwords (user:password)', Colors.RED)}")
        for p in all_passwords:
            print(f"  {colorize(p, Colors.RED)}")

    print()


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Mimikatz Output Beautifier - Parse and display Mimikatz output in NetExec style",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --sam sam.txt
  %(prog)s --lsass lsass.txt --dpapi dpapi.txt
  %(prog)s --sam sam.txt --secrets secrets.txt --lsass lsass.txt --dpapi dpapi.txt
  %(prog)s --sam sam.txt --summary
        """
    )

    parser.add_argument('--sam', metavar='FILE', help='lsadump::sam output file')
    parser.add_argument('--secrets', '--lsa', metavar='FILE', help='lsadump::secrets output file')
    parser.add_argument('--lsass', '--logonpasswords', metavar='FILE', help='sekurlsa::logonpasswords output file')
    parser.add_argument('--dpapi', metavar='FILE', help='sekurlsa::dpapi output file')
    parser.add_argument('--summary', '-s', action='store_true', help='Show copy/paste ready summary at the end')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    args = parser.parse_args()

    # Check if at least one input is provided
    if not any([args.sam, args.secrets, args.lsass, args.dpapi]):
        parser.print_help()
        sys.exit(1)

    # Disable colors if requested
    if args.no_color:
        for attr in dir(Colors):
            if not attr.startswith('_'):
                setattr(Colors, attr, '')

    # Read and process files
    sam_content = None
    secrets_content = None
    lsass_content = None
    dpapi_content = None

    try:
        if args.sam:
            with open(args.sam, 'r') as f:
                sam_content = f.read()
            display_sam(sam_content)

        if args.secrets:
            with open(args.secrets, 'r') as f:
                secrets_content = f.read()
            display_secrets(secrets_content)

        if args.lsass:
            with open(args.lsass, 'r') as f:
                lsass_content = f.read()
            display_lsass(lsass_content)

        if args.dpapi:
            with open(args.dpapi, 'r') as f:
                dpapi_content = f.read()
            display_dpapi(dpapi_content)

        # Show summary if requested
        if args.summary:
            display_summary(sam_content, secrets_content, lsass_content, dpapi_content)

    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error processing file: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
