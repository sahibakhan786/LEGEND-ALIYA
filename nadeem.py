import os
import sys
import time
import uuid
import json
import requests
import random
import string

# ==========================================
# COLORS AND STYLING
# ==========================================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def animated_print(text, delay=0.01, color=GREEN):
    for char in text:
        sys.stdout.write(color + char + RESET)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def show_logo():
    clear_screen()
    logo = f"""
    {CYAN}╔══════════════════════════════════════════════════════════╗
    ║  ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗         ║
    ║  ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║         ║
    ║     ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║         ║
    ║     ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║         ║
    ║     ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║         ║
    ║     ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝         ║
    ╠══════════════════════════════════════════════════════════╣
    ║           {YELLOW}TOKEN GRENADE V7 - NO APPROVAL MODE{CYAN}            ║
    ╚══════════════════════════════════════════════════════════╝{RESET}
    """
    print(logo)

# ==========================================
# CORE GENERATOR
# ==========================================

class FastTokenGen:
    def __init__(self):
        self.session = requests.Session()
        # Realistic User-Agent to avoid 'Invalid Password' error
        self.ua = f"Dalvik/2.1.0 (Linux; U; Android {random.randint(9,13)}; SM-G{random.randint(900,999)}F) [FBAN/FB4A;FBAV/{random.randint(300,400)}.0.0.{random.randint(10,99)};FBPN/com.facebook.katana;FBLC/en_US;FBBV/{random.randint(1000000,9000000)};]"

    def login(self, email, password):
        print(f"\n{YELLOW}[*] Connecting to Facebook Servers...{RESET}")
        
        # Unique device identifiers
        adid = str(uuid.uuid4())
        device_id = str(uuid.uuid4())
        family_id = str(uuid.uuid4())

        # Direct API Login Data
        data = {
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
            "family_device_id": family_id,
            "advertiser_id": adid,
        }

        headers = {
            "User-Agent": self.ua,
            "Content-Type": "application/x-www-form-urlencoded",
            "X-FB-HTTP-Engine": "Liger",
            "X-FB-Connection-Type": "WIFI"
        }

        try:
            response = self.session.post(
                "https://b-api.facebook.com/method/auth.login",
                data=data,
                headers=headers,
                timeout=20
            )
            return response.json()
        except Exception as e:
            return {"error": {"message": str(e)}}

# ==========================================
# MAIN EXECUTION
# ==========================================

def main():
    show_logo()
    
    # Input section
    print(f"{BOLD}{WHITE}┌──────────────────────────────────────────┐{RESET}")
    email = input(f" {GREEN}[?] Email/Phone: {RESET}").strip()
    password = input(f" {GREEN}[?] Password:    {RESET}").strip()
    print(f"{BOLD}{WHITE}└──────────────────────────────────────────┘{RESET}")

    if not email or not password:
        print(f"\n{RED}[✗] Error: Details required!{RESET}")
        return

    gen = FastTokenGen()
    result = gen.login(email, password)

    # Output Handling
    if "access_token" in result:
        token = result["access_token"]
        cookies = result.get("session_cookies")
        
        print(f"\n{GREEN}{'═'*50}{RESET}")
        animated_print("✅ LOGIN SUCCESSFUL! TOKEN GENERATED", color=GREEN)
        print(f"{GREEN}{'═'*50}{RESET}")
        
        print(f"\n{YELLOW}[ ACCESS TOKEN ]{RESET}")
        print(f"{CYAN}{token}{RESET}")
        
        if cookies:
            print(f"\n{YELLOW}[ SESSION COOKIES ]{RESET}")
            cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
            print(f"{WHITE}{cookie_str[:150]}...{RESET}")

        # Save to file automatically
        with open("generated_tokens.txt", "a") as f:
            f.write(f"\nAccount: {email}\nToken: {token}\n{'='*50}\n")
        print(f"\n{BLUE}[i] Saved to generated_tokens.txt{RESET}")

    else:
        error_msg = result.get("error", {}).get("message", "Unknown Error")
        print(f"\n{RED}{'═'*50}{RESET}")
        print(f"{RED}[✗] LOGIN FAILED!{RESET}")
        print(f"{YELLOW}Reason: {RED}{error_msg}{RESET}")
        
        if "checkpoint" in error_msg.lower():
            print(f"{CYAN}[!] Tip: Your account needs manual login/approval on a browser.{RESET}")
        elif "username" in error_msg.lower() or "password" in error_msg.lower():
            print(f"{CYAN}[!] Tip: Re-check your credentials or turn off 2FA.{RESET}")
        print(f"{RED}{'═'*50}{RESET}")

    input(f"\n{MAGENTA}Press Enter to exit...{RESET}")

if __name__ == "__main__":
    main()
