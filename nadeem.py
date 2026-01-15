import os
import requests
import hashlib
import uuid
import json
import time
import random

# Color Codes
Z = "\033[1;30m" # Black
R = "\033[1;31m" # Red
G = "\033[1;32m" # Green
Y = "\033[1;33m" # Yellow
B = "\033[1;34m" # Blue
P = "\033[1;35m" # Purple
C = "\033[1;36m" # Cyan
W = "\033[1;37m" # White

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_sig(params):
    # FB Signature Algorithm
    sig = ""
    for key in sorted(params):
        sig += f"{key}={params[key]}"
    sig += "62f8ce9f74b12f84c123cc23437a4a32"
    return hashlib.md5(sig.encode()).hexdigest()

def run_script():
    clear()
    print(f"{C}==================================================")
    print(f"{W}       {G}TOKEN GRENADE V7 - ULTIMATE BYPASS{W}         ")
    print(f"{C}=================================================={W}")
    
    uid = input(f"{Y}[?] Email/Phone/UID: {G}")
    pas = input(f"{Y}[?] Password:         {G}")
    
    if not uid or not pas:
        print(f"{R}[!] Details missing!")
        return

    print(f"\n{C}[*] Logging in via Secure Tunnel...")
    time.sleep(1)

    # असली एंड्रॉइड डिवाइस जैसा डेटा
    device_id = str(uuid.uuid4())
    adid = str(uuid.uuid4())
    
    data = {
        "adid": adid,
        "format": "json",
        "device_id": device_id,
        "email": uid,
        "password": pas,
        "generate_analytics_claim": "1",
        "generate_machine_id": "1",
        "credentials_type": "password",
        "generate_session_cookies": "1",
        "api_key": "882a8490361da98702bf97a021ddc14d",
        "source_machine_id": str(uuid.uuid4()),
        "method": "auth.login",
        "contact_point": uid,
        "advertiser_id": adid,
        "locale": "en_US",
        "client_country_code": "US",
        "v": "1.0"
    }
    
    data["sig"] = get_sig(data)

    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; SM-G998B Build/SP1A.210812.016) [FBAN/FB4A;FBAV/369.0.0.18.103;FBPN/com.facebook.katana;FBLC/en_US;FBBV/369000000;FBCR/Verizon;FBMF/samsung;FBBD/samsung;FBDV/SM-G998B;FBSV/12;FBCA/arm64-v8a:;FBDM/{density=3.0,width=1080,height=2280};FB_FW/1;FBRV/0;]",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-FB-HTTP-Engine": "Liger",
        "X-FB-Connection-Type": "WIFI",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip"
    }

    try:
        url = "https://b-api.facebook.com/method/auth.login"
        req = requests.post(url, data=data, headers=headers).json()
        
        if "access_token" in req:
            print(f"\n{G}[✓] LOGIN SUCCESSFUL!")
            print(f"{W}--------------------------------------------------")
            print(f"{Y}TOKEN: {C}{req['access_token']}")
            print(f"{W}--------------------------------------------------")
            
            # Cookies extraction
            cookies = req.get("session_cookies")
            if cookies:
                c_str = ";".join([f"{i['name']}={i['value']}" for i in cookies])
                print(f"{Y}COOKIES: {W}{c_str[:50]}...")
            
            with open("token.txt", "w") as f:
                f.write(req['access_token'])
            print(f"\n{G}[!] Token saved to token.txt")

        elif "error_msg" in req:
            error = req["error_msg"]
            if "checkpoint" in error.lower():
                print(f"\n{R}[✗] ACCOUNT LOCKED (Checkpoint)!")
                print(f"{Y}ID ब्राउज़र में लॉगिन करें और 'Yes, it was me' पर क्लिक करें।")
            else:
                print(f"\n{R}[✗] ERROR: {error}")
        else:
            print(f"\n{R}[✗] UNKNOWN ERROR: {json.dumps(req)}")

    except Exception as e:
        print(f"\n{R}[!] Connection Error: {e}")

    input(f"\n{P}Press Enter to exit...")

if __name__ == "__main__":
    run_script()
