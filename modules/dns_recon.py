import dns.resolver
import dns.zone
import dns.query

from urllib.parse import urlparse
from colorama import Fore, Style

def check_spf_dmarc(domain, results):
    """Check for SPF and DMARC records via TXT."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_found = False
        for rdata in answers:
            txt = rdata.to_text()
            if "v=spf1" in txt:
                spf_found = True
                res = f"SPF record found: {txt}"
                print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] {res}")
                results.append({"type": "dns_spf", "desc": res, "severity": "Info"})
        
        if not spf_found:
            res = f"No SPF record found for {domain} (Susceptible to spoofing)"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "dns_spf_missing", "desc": res, "severity": "Medium"})
            
    except Exception:
        res = f"Failed to retrieve TXT records (SPF check) for {domain}"
        results.append({"type": "dns_txt_error", "desc": res, "severity": "Info"})

    # DMARC check
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_found = False
        for rdata in answers:
            txt = rdata.to_text()
            if "v=DMARC1" in txt:
                dmarc_found = True
                res = f"DMARC record found: {txt}"
                print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] {res}")
                results.append({"type": "dns_dmarc", "desc": res, "severity": "Info"})
                
        if not dmarc_found:
            res = f"No DMARC record found for {domain} (Susceptible to spoofing)"
            print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
            results.append({"type": "dns_dmarc_missing", "desc": res, "severity": "Medium"})
    except Exception:
        res = f"No DMARC record found for {domain} (Susceptible to spoofing)"
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] {res}")
        results.append({"type": "dns_dmarc_missing", "desc": res, "severity": "Medium"})


def check_zone_transfer(domain, results):
    """Attempt a DNS Zone Transfer (AXFR)."""
    try:
        ns_answers = dns.resolver.resolve(domain, 'NS')
        ns_servers = [rdata.target.to_text() for rdata in ns_answers]
        
        for ns in ns_servers:
            try:
                ns_ip = dns.resolver.resolve(ns, 'A')[0].to_text()
                z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                if z:
                    res = f"Zone Transfer (AXFR) SUCCESSFUL on {ns} ({ns_ip})! This exposes all DNS records."
                    print(f"  [{Fore.RED}!{Style.RESET_ALL}] {res}")
                    results.append({"type": "dns_axfr", "desc": res, "severity": "High"})
                    return
            except Exception:
                pass
        
        print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] Zone Transfer (AXFR) failed (Good, server is secure).")
    except Exception:
        pass


def get_subdomains_crtsh(domain, results, session):
    """Fetch subdomains from crt.sh Certificate Transparency logs."""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = session.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            subdomains = set()
            for entry in data:
                name_value = entry.get('name_value', '')
                for sub in name_value.split('\n'):
                    if '*' not in sub:
                        subdomains.add(sub.strip().lower())
            
            if subdomains:
                res = f"Discovered {len(subdomains)} subdomains via crt.sh (Certificate Transparency)"
                print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] {res}")
                results.append({"type": "dns_subdomains", "desc": res + f": {', '.join(list(subdomains)[:10])}...", "severity": "Info"})
    except Exception:
        print(f"  [{Fore.YELLOW}!{Style.RESET_ALL}] Failed to fetch subdomains from crt.sh")


def run_dns_recon(target_url, session=None):
    """
    Main DNS Recon Module.
    Gathers standard records, checks SPF/DMARC, tries AXFR, and fetches subdomains.
    """
    print(f"\n[{Fore.BLUE}*{Style.RESET_ALL}] Running DNS Reconnaissance Module...")
    if session is None:
        import requests as session

    results = []
    domain = urlparse(target_url).netloc.split(':')[0]
    if domain.startswith("www."):
        domain = domain[4:]
        
    print(f"  [{Fore.BLUE}*{Style.RESET_ALL}] Target domain for DNS: {domain}")

    # Standard Records (A, AAAA, MX, NS)
    for record_type in ['A', 'AAAA', 'MX', 'NS']:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = [rdata.to_text() for rdata in answers]
            res = f"DNS {record_type} records: {', '.join(records)}"
            print(f"  [{Fore.GREEN}+{Style.RESET_ALL}] {res}")
            results.append({"type": f"dns_{record_type.lower()}", "desc": res, "severity": "Info"})
        except Exception:
            pass

    # Security Checks
    check_spf_dmarc(domain, results)
    check_zone_transfer(domain, results)
    
    # OSINT / Subdomains
    get_subdomains_crtsh(domain, results, session)
    
    return results
