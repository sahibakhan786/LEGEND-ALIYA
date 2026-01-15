import os
import sys
import time
import uuid
import json
import requests
import hashlib
import random

# COLORS
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def generate_sig(data):
    """फेसबुक की सुरक्षा को बायपास करने के लिए सिग्नेचर जनरेट करना"""
    data_str = "".join(f"{k}={v}" for k, v in sorted(data.items()))
    data_str += "62f8ce9f74b12f84c123cc23437a4a32" # App Secret
    return hashlib.md5(data_str.encode()).hexdigest()

def get_token():
    clear()
    print(f"{CYAN}=================================================={RESET}")
    print(f"{GREEN}          TOKEN GRENADE V7 - FIX ERROR            {RESET}")
    print(f"{CYAN}=================================================={RESET}")
    
    email = input(f"{YELLOW}[?] Email/Phone: {RESET}").strip()
    password = input(f"{YELLOW}[?] Password:    {RESET}").strip()
    
    if not email or not password:
        print(f"{RED}[!] Missing Information!{RESET}")
        return

    print(f"\n{BLUE}[*] Authorizing with Facebook Servers...{RESET}")
    
    device_id = str(uuid.uuid4())
    adid = str(uuid.uuid4())
    
    # यह डेटा सीधे FB Android App से लिया गया है
    params = {
        "api_key": "882a8490361da98702bf97a021ddc14d",
        "credentials_type": "password",
        "email": email,
        "format": "json",
        "generate_machine_id": "1",
        "generate_session_cookies": "1",
        "locale": "en_US",
        "method": "auth.login",
        "password": password,
        "return_ssl_resources": "0",
        "v": "1.0",
        "adid": adid,
        "device_id": device_id,
    }
    
    params["sig"] = generate_sig(params)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.181 Mobile Safari/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-FB-HTTP-Engine": "Liger"
    }

    try:
        response = requests.post("https://graph.facebook.com/auth/login", data=params, headers=headers)
        data = response.json()
        
        if "access_token" in data:
            print(f"\n{GREEN}[✓] SUCCESS! TOKEN FOUND:{RESET}")
            print(f"{CYAN}{data['access_token']}{RESET}")
            
            with open("token.txt", "w") as f:
                f.write(data['access_token'])
            print(f"\n{BLUE}[i] Saved to token.txt{RESET}")
            
        elif "error_msg" in data:
            print(f"\n{RED}[✗] ERROR: {data['error_msg']}{RESET}")
        else:
            print(f"\n{RED}[✗] ERROR: {json.dumps(data, indent=2)}{RESET}")
            
    except Exception as e:
        print(f"{RED}[!] Connection Failed: {e}{RESET}")

if __name__ == "__main__":
    get_token()
