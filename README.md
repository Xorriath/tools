## brute_calcom.py

This is a tool I built to assess the security of the login functionality of the calcom application. It dinamically gets all cookies and parameters required to send login attempts, then it uses the provided username and wordlist to launch a bruteforce attack using ffuf.
The calcom application implements throttling by default, so this attack would take a long time, but there is still a chance of exploitation when using a small targeted password list.

## get_all_users.sh

When enumerating Active Directory users using either rpc or ldap, I noticed that sometimes a method might show users the other does not, most commonly the ldap method also grabs the machine accounts of the domain computers, whereas the rpc method does not. This tool queries AD via both rpc using netexec and ldap using ldapsearch and combines the results in a sorted list.
