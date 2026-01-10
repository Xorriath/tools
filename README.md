## brute_calcom.py

This is a tool I built to assess the security of the login functionality of the calcom application. It dinamically gets all cookies and parameters required to send login attempts, then it uses the provided username and wordlist to launch a bruteforce attack using ffuf.
The calcom application implements throttling by default, so this attack would take a long time, but there is still a chance of exploitation when using a small targeted password list.

## get_all_users.sh

When enumerating Active Directory users using either rpc or ldap, I noticed that sometimes a method might show users the other does not, most commonly the ldap method also grabs the machine accounts of the domain computers, whereas the rpc method does not. This tool queries AD via both rpc using netexec and ldap using ldapsearch and combines the results in a sorted list.

## Package-CVE-Checker-Installed.py

This tool grabs a list of all the packes installed on a Debian based system ("apt list --installed"), then checks all the packages and their versions for known CVEs, based on the selected CVSS score(default 7+) using the Vulners API. For CVEs related to local privilege escalation vulnerabilities, I recommend setting the --CVSS flag to 8+.The free Vulners API key has some rate limitting, which the tool accounts for so it may take some time to run, naturally with a paid key it would run much faster. The results are saved in a nicely formatted markdown file.

## LFI_basic_fuzz.txt

A payload list useful for fuzzing file inclusion parameters.

## suBF.sh

Updated suBF.sh script to allow for cluster bomb and pichfork password modes, from the original authors at https://github.com/carlospolop/su-bruteforce/blob/master/suBF.sh.
