import random
import string
import json
import time
import requests
import uuid
import base64
import io
import struct
import sys
import os

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
UNDERLINE = "\033[4m"

def animated_print(text, delay=0.003, color=GREEN):
    """Prints text with a typewriter animation effect."""
    for char in text:
        sys.stdout.write(color + char + RESET)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def loading_animation(text="PROCESSING", duration=2):
    """Displays a professional loading animation."""
    chars = ["▰▱▱▱▱", "▰▰▱▱▱", "▰▰▰▱▱", "▰▰▰▰▱", "▰▰▰▰▰", "▰▰▰▰▱", "▰▰▰▱▱", "▰▰▱▱▱", "▰▱▱▱▱"]
    end_time = time.time() + duration
    while time.time() < end_time:
        for char in chars:
            sys.stdout.write(f"\r{MAGENTA}[{char}] {BOLD}{text}...{RESET}")
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write("\r" + " " * 60 + "\r")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_logo():
    clear_screen()
    logo = f"""
    {MAGENTA}╔══════════════════════════════════════════════════════════╗{RESET}
    {MAGENTA}║{CYAN}      ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗      {MAGENTA}║{RESET}
    {MAGENTA}║{CYAN}      ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║      {MAGENTA}║{RESET}
    {MAGENTA}║{CYAN}         ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║      {MAGENTA}║{RESET}
    {MAGENTA}║{CYAN}         ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║      {MAGENTA}║{RESET}
    {MAGENTA}║{CYAN}         ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║      {MAGENTA}║{RESET}
    {MAGENTA}║{CYAN}         ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝      {MAGENTA}║{RESET}
    {MAGENTA}║{YELLOW}      ██████╗ ██████╗ ███████╗███╗   ██╗ █████╗ ██████╗ ███████╗{MAGENTA}║{RESET}
    {MAGENTA}║{YELLOW}     ██╔════╝ ██╔══██╗██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔════╝{MAGENTA}║{RESET}
    {MAGENTA}║{YELLOW}     ██║  ███╗██████╔╝█████╗  ██╔██╗ ██║███████║██║  ██║█████╗  {MAGENTA}║{RESET}
    {MAGENTA}║{YELLOW}     ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║██╔══██║██║  ██║██╔══╝  {MAGENTA}║{RESET}
    {MAGENTA}║{YELLOW}     ╚██████╔╝██║  ██║███████╗██║ ╚████║██║  ██║██████╔╝███████╗{MAGENTA}║{RESET}
    {MAGENTA}║{GREEN}     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝{MAGENTA}║{RESET}
    {MAGENTA}║{BLUE}               TOKEN GRENADE V7 - ULTIMATE EDITION              {MAGENTA}║{RESET}
    {MAGENTA}║{CYAN}                 DEVELOPED BY: ALIYA×NADEEM                    {MAGENTA}║{RESET}
    {MAGENTA}╚══════════════════════════════════════════════════════════╝{RESET}
    """
    print(logo)
    time.sleep(0.5)

# ==========================================
# CRYPTO CHECK
# ==========================================
try:
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except ImportError:
    print(f"{RED}[✗] ERROR: 'pycryptodome' module not found.{RESET}")
    print(f"{YELLOW}[+] Run: pip install pycryptodome{RESET}")
    exit()

# ==========================================
# MAIN TOKEN GENERATOR CLASS
# ==========================================

class TokenGrenadeV7:
    def __init__(self):
        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())
        self.machine_id = ''.join(random.choices(string.ascii_letters + string.digits, k=24))
        self.adid = str(uuid.uuid4())
        self.sim_serial = ''.join(random.choices(string.digits, k=20))
        
    def get_public_key(self):
        try:
            url = 'https://b-graph.facebook.com/pwd_key_fetch'
            params = {
                'version': '2',
                'flow': 'CONTROLLER_INITIALIZATION',
                'method': 'GET',
                'fb_api_req_friendly_name': 'pwdKeyFetch',
                'fb_api_caller_class': 'com.facebook.auth.login.AuthOperations',
                'access_token': '438142079694454|fc0a7caa49b192f64f6f5a6d9643bb28'
            }
            response = requests.post(url, params=params).json()
            return response.get('public_key'), str(response.get('key_id', '25'))
        except:
            return None, "25"

    def encrypt_password(self, password):
        try:
            public_key, key_id = self.get_public_key()
            if not public_key:
                raise Exception("Could not fetch public key")

            rand_key = get_random_bytes(32)
            iv = get_random_bytes(12)
            
            pubkey = RSA.import_key(public_key)
            cipher_rsa = PKCS1_v1_5.new(pubkey)
            encrypted_rand_key = cipher_rsa.encrypt(rand_key)
            
            cipher_aes = AES.new(rand_key, AES.MODE_GCM, nonce=iv)
            current_time = int(time.time())
            cipher_aes.update(str(current_time).encode())
            encrypted_passwd, auth_tag = cipher_aes.encrypt_and_digest(password.encode())
            
            buf = io.BytesIO()
            buf.write(bytes([1, int(key_id)]))
            buf.write(iv)
            buf.write(struct.pack("<h", len(encrypted_rand_key)))
            buf.write(encrypted_rand_key)
            buf.write(auth_tag)
            buf.write(encrypted_passwd)
            
            encoded = base64.b64encode(buf.getvalue()).decode()
            return f"#PWD_FB4A:2:{current_time}:{encoded}"
        except Exception as e:
            raise Exception(f"Encryption error: {e}")

    def login_to_facebook(self, email, password):
        """Main login function that returns ALL tokens directly"""
        
        loading_animation("CONNECTING TO FACEBOOK")
        
        # Encrypt password
        try:
            encrypted_pass = self.encrypt_password(password)
        except:
            encrypted_pass = password
        
        # Build headers
        headers = {
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-G973F Build/RP1A.200720.012) [FBAN/FB4A;FBAV/350.0.0.36.107;FBPN/com.facebook.katana;FBLC/en_US;FBBV/1;FBCR/Telenor;FBMF/samsung;FBBD/samsung;FBDV/SM-G973F;FBSV/11;FBCA/arm64-v8a:;FBDM/{density=3.0,width=1080,height=2028};FB_FW/1;FBRV/0;]",
            "x-fb-http-engine": "Liger",
            "x-fb-connection-type": "WIFI",
            "x-fb-connection-quality": "EXCELLENT"
        }
        
        # Build login data
        data = {
            "format": "json",
            "email": email,
            "password": encrypted_pass,
            "credentials_type": "password",
            "generate_session_cookies": "1",
            "generate_analytics_claim": "1",
            "locale": "en_US",
            "client_country_code": "US",
            "api_key": "882a8490361da98702bf97a021ddc14d",
            "access_token": "350685531728|62f8ce9f74b12f84c123cc23437a4a32",
            "device_id": self.device_id,
            "family_device_id": self.device_id,
            "secure_family_device_id": str(uuid.uuid4()),
            "machine_id": self.machine_id,
            "jazoest": ''.join(random.choices(string.digits, k=5)),
            "adid": self.adid,
            "advertiser_id": self.adid,
            "sim_serials": f'["{self.sim_serial}"]',
            "fb_api_req_friendly_name": "authenticate",
            "fb_api_caller_class": "Fb4aAuthHandler",
            "sig": "214049b9f17c38bd767de53752b53946",
            "cpl": "true",
            "try_num": "1",
            "currently_logged_in_userid": "0"
        }
        
        loading_animation("LOGGING IN")
        
        try:
            response = self.session.post(
                "https://b-graph.facebook.com/auth/login",
                headers=headers,
                data=data,
                timeout=30
            )
            
            result = response.json()
            
            if 'access_token' in result:
                original_token = result['access_token']
                
                # Extract token prefix
                prefix = ""
                for i, char in enumerate(original_token):
                    if char.islower():
                        prefix = original_token[:i]
                        break
                
                # Get cookies
                cookies_dict = {}
                cookies_string = ""
                if 'session_cookies' in result:
                    for cookie in result['session_cookies']:
                        cookies_dict[cookie['name']] = cookie['value']
                        cookies_string += f"{cookie['name']}={cookie['value']}; "
                
                return {
                    'success': True,
                    'original_token': {
                        'token': original_token,
                        'prefix': prefix,
                        'type': 'FB_ANDROID'
                    },
                    'cookies': cookies_string.rstrip('; '),
                    'session': self.session
                }
            else:
                error_msg = result.get('error', {}).get('message', 'Invalid credentials')
                return {
                    'success': False,
                    'error': error_msg
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def generate_all_tokens(self, original_token):
        """Generate tokens for all Facebook apps"""
        
        tokens = {}
        
        # App configurations
        apps = {
            'FACEBOOK_ANDROID': '350685531728',
            'MESSENGER_ANDROID': '256002347743983',
            'FACEBOOK_LITE': '275254692598279',
            'MESSENGER_LITE': '200424423651082',
            'ADS_MANAGER': '438142079694454',
            'PAGES_MANAGER': '121876164619130',
            'INSTAGRAM_ANDROID': '567067343352427',
            'WHATSAPP_BUSINESS': '306646696174006',
            'WORKPLACE': '120121171331514',
            'OCULUS': '333903456733940'
        }
        
        loading_animation("GENERATING ALL TOKENS", 3)
        
        for app_name, app_id in apps.items():
            try:
                response = requests.post(
                    'https://api.facebook.com/method/auth.getSessionforApp',
                    data={
                        'access_token': original_token,
                        'format': 'json',
                        'new_app_id': app_id,
                        'generate_session_cookies': '1'
                    },
                    timeout=10
                )
                
                result = response.json()
                
                if 'access_token' in result:
                    token = result['access_token']
                    
                    # Extract prefix
                    prefix = ""
                    for i, char in enumerate(token):
                        if char.islower():
                            prefix = token[:i]
                            break
                    
                    # Get cookies for this app
                    app_cookies = ""
                    if 'session_cookies' in result:
                        for cookie in result['session_cookies']:
                            app_cookies += f"{cookie['name']}={cookie['value']}; "
                    
                    tokens[app_name] = {
                        'token': token,
                        'prefix': prefix,
                        'app_id': app_id,
                        'cookies': app_cookies.rstrip('; ')
                    }
                    
                    print(f"{GREEN}[✓] {YELLOW}{app_name:<20} {GREEN}Generated{RESET}")
                    time.sleep(0.2)
                    
            except:
                print(f"{RED}[✗] {YELLOW}{app_name:<20} {RED}Failed{RESET}")
        
        return tokens

# ==========================================
# DISPLAY FUNCTIONS
# ==========================================

def print_section_header(title):
    print(f"\n{MAGENTA}{'╔' + '═' * 58 + '╗'}{RESET}")
    print(f"{MAGENTA}║{CYAN}{BOLD}{title.center(58)}{RESET}{MAGENTA}║{RESET}")
    print(f"{MAGENTA}{'╚' + '═' * 58 + '╝'}{RESET}")

def print_token(token_data, app_name=None):
    if app_name:
        print(f"\n{YELLOW}┌─[{GREEN}APP{YELLOW}]─[{CYAN}{app_name}{YELLOW}]{'─' * (30 - len(app_name))}┐{RESET}")
    else:
        print(f"\n{YELLOW}┌{'─' * 56}┐{RESET}")
    
    print(f"{YELLOW}│{RESET} {GREEN}TYPE:{RESET} {CYAN}{token_data.get('prefix', 'N/A')}{RESET}")
    
    token = token_data.get('token', '')
    if len(token) > 50:
        print(f"{YELLOW}│{RESET} {GREEN}TOKEN:{RESET}")
        print(f"{YELLOW}│{RESET} {CYAN}{token[:50]}...{RESET}")
        print(f"{YELLOW}│{RESET} {CYAN}...{token[-50:]}{RESET}")
    else:
        print(f"{YELLOW}│{RESET} {GREEN}TOKEN:{RESET} {CYAN}{token}{RESET}")
    
    if token_data.get('cookies'):
        print(f"{YELLOW}│{RESET} {GREEN}COOKIES:{RESET} {token_data.get('cookies')[:50]}...{RESET}")
    
    if app_name:
        print(f"{YELLOW}└{'─' * 56}┘{RESET}")
    else:
        print(f"{YELLOW}└{'─' * 56}┘{RESET}")

def save_to_file(tokens, original_data, email):
    filename = f"TOKENS_{int(time.time())}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write("TOKEN GRENADE V7 - ALL GENERATED TOKENS\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Account: {email}\n")
        f.write(f"Generated: {time.ctime()}\n")
        f.write("-" * 60 + "\n\n")
        
        f.write("ORIGINAL TOKEN:\n")
        f.write(f"Type: {original_data['original_token']['prefix']}\n")
        f.write(f"Token: {original_data['original_token']['token']}\n\n")
        
        f.write("COOKIES:\n")
        f.write(f"{original_data.get('cookies', 'N/A')}\n\n")
        
        f.write("=" * 60 + "\n")
        f.write("ALL CONVERTED TOKENS:\n")
        f.write("=" * 60 + "\n\n")
        
        for app_name, token_data in tokens.items():
            f.write(f"{app_name}:\n")
            f.write(f"Type: {token_data.get('prefix', 'N/A')}\n")
            f.write(f"Token: {token_data.get('token', 'N/A')}\n")
            f.write(f"Cookies: {token_data.get('cookies', 'N/A')}\n")
            f.write("-" * 40 + "\n\n")
    
    return filename

# ==========================================
# MAIN EXECUTION
# ==========================================

def main():
    show_logo()
    
    # Animated welcome message
    print(f"{GREEN}{'═' * 60}{RESET}")
    animated_print(f"{CYAN}{BOLD}     WELCOME TO TOKEN GRENADE V7     {RESET}", color=CYAN)
    animated_print(f"{YELLOW}     DIRECT TOKEN GENERATOR      {RESET}", color=YELLOW)
    print(f"{GREEN}{'═' * 60}{RESET}")
    
    # Get credentials
    print(f"\n{YELLOW}┌{'─' * 58}┐{RESET}")
    print(f"{YELLOW}│{GREEN} ENTER YOUR FACEBOOK CREDENTIALS {YELLOW}│{RESET}")
    print(f"{YELLOW}└{'─' * 58}┘{RESET}")
    
    email = input(f"\n{GREEN}[?] {CYAN}Email/Phone: {RESET}").strip()
    password = input(f"{GREEN}[?] {CYAN}Password: {RESET}").strip()
    
    if not email or not password:
        print(f"\n{RED}[✗] ERROR: Both fields are required!{RESET}")
        return
    
    print(f"\n{YELLOW}{'═' * 60}{RESET}")
    animated_print(f"{CYAN}Starting token generation process...{RESET}", color=CYAN)
    print(f"{YELLOW}{'═' * 60}{RESET}")
    
    # Create generator instance
    generator = TokenGrenadeV7()
    
    # Step 1: Login
    print(f"\n{GREEN}[1/3] {CYAN}Logging into Facebook...{RESET}")
    login_result = generator.login_to_facebook(email, password)
    
    if not login_result['success']:
        print(f"\n{RED}{'═' * 60}{RESET}")
        animated_print(f"{RED}[✗] LOGIN FAILED!{RESET}", color=RED)
        print(f"{RED}{'═' * 60}{RESET}")
        print(f"\n{YELLOW}Error: {RED}{login_result.get('error', 'Unknown error')}{RESET}")
        print(f"\n{GREEN}Possible solutions:{RESET}")
        print(f"{CYAN}1. Check your email/phone and password{RESET}")
        print(f"{CYAN}2. Make sure your account is active{RESET}")
        print(f"{CYAN}3. Try using Facebook app first{RESET}")
        print(f"{YELLOW}{'═' * 60}{RESET}")
        return
    
    print(f"{GREEN}[✓] {CYAN}Login successful!{RESET}")
    
    # Step 2: Generate all tokens
    print(f"\n{GREEN}[2/3] {CYAN}Generating all application tokens...{RESET}")
    all_tokens = generator.generate_all_tokens(login_result['original_token']['token'])
    
    print(f"{GREEN}[✓] {CYAN}All tokens generated!{RESET}")
    
    # Step 3: Display results
    print(f"\n{GREEN}[3/3] {CYAN}Displaying results...{RESET}")
    time.sleep(1)
    
    clear_screen()
    show_logo()
    
    # Success banner
    print(f"{GREEN}{'╔' + '═' * 58 + '╗'}{RESET}")
    print(f"{GREEN}║{CYAN}{BOLD}✅ LOGIN SUCCESSFUL - ALL TOKENS GENERATED ✅{RESET}{GREEN}║{RESET}")
    print(f"{GREEN}{'╚' + '═' * 58 + '╝'}{RESET}")
    
    # Original token
    print_section_header("ORIGINAL TOKEN")
    print_token(login_result['original_token'])
    
    # All converted tokens
    if all_tokens:
        print_section_header(f"ALL GENERATED TOKENS ({len(all_tokens)} APPS)")
        
        for app_name, token_data in all_tokens.items():
            print_token(token_data, app_name)
            time.sleep(0.1)
    
    # Cookies
    if login_result.get('cookies'):
        print_section_header("SESSION COOKIES")
        print(f"\n{GREEN}{login_result['cookies'][:100]}...{RESET}")
        if len(login_result['cookies']) > 100:
            print(f"{GREEN}...{login_result['cookies'][-100:]}{RESET}")
    
    # Summary
    print_section_header("GENERATION SUMMARY")
    print(f"\n{GREEN}✓ Original Token: {login_result['original_token']['prefix']}{RESET}")
    print(f"{GREEN}✓ Total Apps: {len(all_tokens)}{RESET}")
    print(f"{GREEN}✓ Account: {email}{RESET}")
    print(f"{GREEN}✓ Time: {time.ctime()}{RESET}")
    
    # Save option
    print_section_header("SAVE OPTIONS")
    choice = input(f"\n{YELLOW}[?] Save all tokens to file? (y/N): {RESET}").strip().lower()
    
    if choice == 'y':
        filename = save_to_file(all_tokens, login_result, email)
        print(f"\n{GREEN}[✓] All tokens saved to: {CYAN}{filename}{RESET}")
    
    # Final message
    print(f"\n{MAGENTA}{'═' * 60}{RESET}")
    animated_print(f"{CYAN}🎉 TOKEN GENERATION COMPLETE! 🎉", color=CYAN)
    animated_print(f"{YELLOW}Thank you for using Token Grenade V7", color=YELLOW)
    print(f"{MAGENTA}{'═' * 60}{RESET}")
    
    # Quick stats
    print(f"\n{GREEN}📊 Quick Stats:{RESET}")
    print(f"{CYAN}├─ Total Tokens: {len(all_tokens) + 1}{RESET}")
    print(f"{CYAN}├─ Original Type: {login_result['original_token']['prefix']}{RESET}")
    print(f"{CYAN}└─ Generation Time: {time.strftime('%H:%M:%S')}{RESET}")
    
    print(f"\n{YELLOW}{'═' * 60}{RESET}")
    print(f"{GREEN}Made with ❤️ by ALIYA×NADEEM{RESET}")
    print(f"{YELLOW}{'═' * 60}{RESET}")

# ==========================================
# RUN SCRIPT
# ==========================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{RED}[!] Process interrupted by user{RESET}")
        print(f"{YELLOW}Thank you for using Token Grenade V7{RESET}")
    except Exception as e:
        print(f"\n{RED}[✗] Unexpected error: {e}{RESET}")
    
    # Exit gracefully
    input(f"\n{BLUE}Press Enter to exit...{RESET}")
