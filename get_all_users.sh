#!/usr/bin/env bash

if [ "$#" -ne 4 ]; then
    echo "Usage: $0 <DC IP> <username> <password> <domain name>"
    exit 1
fi

# Setting Variables
DC_IP=$1
USERNAME=$2
PASSWORD=$3
DOMAIN_NAME=$4

# Checking if credentials are correct
echo "[+] Checking credentials..."
nxc ldap "$DC_IP" -u "$USERNAME" -p "$PASSWORD" > check_output.txt
second_line=$(head -n 2 check_output.txt | tail -n 1)
if ! echo "$second_line" | grep -q "[+]"; then
    echo "[-] Login failed, check the credentials."
    exit 1
fi

# Getting users via rpc using netexec
echo "[+] Enumerating users via rpc using netexec..."
nxc ldap "$DC_IP" -u "$USERNAME" -p "$PASSWORD" --users > tmp1.txt
tail -n +5 tmp1.txt | awk -F' ' '{print $5}' > rpcusers.txt

# Getting users via ldap using ldapsearch
echo "[+] Enumerating users via ldap using ldapsearch..."
# Dynamically construct the base DN for domains with multiple components
base_dn="DC=${DOMAIN_NAME//./,DC=}"
ldapsearch -x -H "ldap://$DC_IP" -D "$USERNAME@$DOMAIN_NAME" -w "$PASSWORD" -b "$base_dn" -s sub "(objectClass=user)" > tmp2.txt
grep -i "samaccountname" tmp2.txt | awk -F' ' '{print $2}' > ldapusers.txt

# Combine the two lists
echo "[+] Combining the user lists..."
cat rpcusers.txt ldapusers.txt | sort -u > fullusers.txt
rm tmp1.txt tmp2.txt rpcusers.txt ldapusers.txt check_output.txt
echo "[+] Done, enumerated users via rpc and ldap into a single list fullusers.txt and removed duplicates!"
