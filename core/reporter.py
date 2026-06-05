import json
import os
from datetime import datetime
from jinja2 import Template

def get_explanation(vuln_type):
    if not vuln_type:
        return "A security vulnerability or misconfiguration was identified."
    vuln_type = vuln_type.lower()
    if 'sql' in vuln_type or 'sqli' in vuln_type:
        return "SQL Injection allows an attacker to interfere with database queries, potentially leading to unauthorized data access, modification, or deletion."
    elif 'xss' in vuln_type:
        return "Cross-Site Scripting (XSS) enables attackers to inject malicious scripts into web pages viewed by others, leading to session hijacking or sensitive data theft."
    elif 'lfi' in vuln_type or 'file' in vuln_type:
        return "Local File Inclusion (LFI) allows an attacker to read arbitrary files on the server, potentially exposing configuration files or source code."
    elif 'cors' in vuln_type:
        return "Cross-Origin Resource Sharing (CORS) misconfigurations can allow unauthorized domains to access sensitive resources or perform actions on behalf of authenticated users."
    elif 'redirect' in vuln_type:
        return "Open Redirects occur when an application improperly validates user-supplied input used in redirection, potentially facilitating phishing attacks."
    elif 'xmlrpc' in vuln_type:
        return "XML-RPC functionality is enabled. This can be leveraged for Pingback Server-Side Request Forgery (SSRF) or amplification attacks."
    elif 'cve' in vuln_type:
        return "A publicly disclosed vulnerability (CVE) has been detected. Exploitation could lead to various severe impacts ranging from data leaks to complete system compromise depending on the specific CVE."
    elif 'cron' in vuln_type:
        return "Accessible cron scripts (e.g., wp-cron.php) can be triggered externally, potentially serving as a vector for application-level Denial of Service (DDoS)."
    elif 'admin' in vuln_type:
        return "Administrative interfaces are publicly accessible. It is recommended to restrict access to trusted IP addresses only to prevent unauthorized access."
    elif 'elementor' in vuln_type:
        return "Vulnerabilities within the Elementor plugin can range from XSS to privilege escalation, potentially allowing an attacker to compromise the application."
    elif 'iis' in vuln_type:
        return "IIS specific misconfigurations or vulnerabilities were detected, which could lead to unauthorized access or information disclosure."
    elif 'header' in vuln_type:
        return "Missing or improperly configured HTTP security headers leave the application susceptible to attacks such as clickjacking or MIME-sniffing."
    elif 'info' in vuln_type or 'disclosure' in vuln_type:
        return "Information disclosure occurs when an application fails to adequately protect sensitive and confidential information from being revealed to unauthorized users."
    elif 'dns_spf' in vuln_type or 'dns_dmarc' in vuln_type:
        return "Missing or misconfigured SPF/DMARC records can allow attackers to spoof the domain in email communications, leading to phishing and social engineering attacks."
    elif 'dns_axfr' in vuln_type or 'zone transfer' in vuln_type:
        return "A DNS Zone Transfer (AXFR) vulnerability allows an attacker to retrieve the entire DNS zone file for a domain, exposing internal networks, subdomains, and server IP addresses."
    elif 'dns' in vuln_type or 'subdomain' in vuln_type:
        return "DNS records and subdomains were discovered, which can map out the target's infrastructure and reveal potentially vulnerable, forgotten, or hidden services."
    elif 'info_exploit_file' in vuln_type:
        return "Critical sensitive files (such as backups, logs, or environment configurations) were successfully extracted. These files often contain hardcoded credentials and secrets."
    elif 'db_credentials_stolen' in vuln_type:
        return "Database credentials (username, password, host) were successfully extracted from a backup or configuration file. This exposes the entire database to potential compromise."
    elif 'db_admin_exposed' in vuln_type:
        return "A public database administration interface (e.g., phpMyAdmin, Adminer) was discovered while possessing valid credentials. This provides immediate, full access to view, modify, and delete the database."
    elif 'lfi_rce_chain' in vuln_type:
        return "An autonomous attack chain successfully escalated a Local File Inclusion (LFI) vulnerability into Remote Code Execution (RCE) via Log Poisoning. The server is completely compromised."
    elif 'ssrf_full_metadata' in vuln_type:
        return "A Full SSRF vulnerability allowed the extraction of Cloud Metadata (e.g. AWS IAM keys). This implies a total compromise of the cloud hosting environment."
    else:
        return "A security vulnerability or misconfiguration was identified that could be leveraged by an attacker to impact the confidentiality, integrity, or availability of the application."

class Reporter:
    def __init__(self, target_url, results):
        self.target_url = target_url
        self.results = results
        self.report_dir = "reports"
        
        if not os.path.exists(self.report_dir):
            os.makedirs(self.report_dir)

    def _generate_html(self, json_file):
        html_template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Vulnerability Assessment Report - {{ target }}</title>
            <style>
                body { 
                    font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; 
                    background-color: #f9f9f9; color: #333; margin: 0; padding: 20px;
                    line-height: 1.6;
                }
                .container { 
                    max-width: 1000px; margin: 0 auto; background: #fff;
                    padding: 40px; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }
                .header {
                    border-bottom: 2px solid #2c3e50; padding-bottom: 20px; margin-bottom: 30px;
                }
                .header h1 { 
                    color: #2c3e50; font-size: 28px; margin: 0 0 10px 0;
                }
                .header p { color: #555; margin: 5px 0; }
                .target { font-weight: bold; color: #2980b9; }

                .summary-table {
                    width: 100%; border-collapse: collapse; margin-bottom: 30px;
                }
                .summary-table th, .summary-table td {
                    border: 1px solid #ddd; padding: 12px; text-align: center;
                }
                .summary-table th { background-color: #f2f2f2; font-weight: bold; color: #333; }
                .val-Critical { color: #c0392b; font-weight: bold; }
                .val-High { color: #e67e22; font-weight: bold; }
                .val-Medium { color: #f39c12; font-weight: bold; }
                .val-Low { color: #27ae60; font-weight: bold; }
                .val-Info { color: #3498db; font-weight: bold; }

                .section {
                    margin-bottom: 40px;
                }
                .section h2 {
                    color: #2c3e50; font-size: 22px; border-bottom: 1px solid #eee;
                    padding-bottom: 10px; margin-bottom: 20px;
                }
                .empty { color: #7f8c8d; font-style: italic; }

                .vuln-card {
                    border-left: 4px solid #ddd; padding: 15px; margin-bottom: 20px;
                    background-color: #fafafa; border-radius: 0 4px 4px 0;
                }
                .vuln-Critical { border-left-color: #c0392b; }
                .vuln-High { border-left-color: #e67e22; }
                .vuln-Medium { border-left-color: #f39c12; }
                .vuln-Low { border-left-color: #27ae60; }
                .vuln-Info { border-left-color: #3498db; }

                .badge {
                    display: inline-block; padding: 4px 8px; border-radius: 3px;
                    font-size: 12px; font-weight: bold; color: #fff; margin-bottom: 10px;
                }
                .bg-Critical { background: #c0392b; }
                .bg-High { background: #e67e22; }
                .bg-Medium { background: #f39c12; }
                .bg-Low { background: #27ae60; }
                .bg-Info { background: #3498db; }

                .vuln-type { font-weight: bold; color: #34495e; margin-bottom: 5px; }
                .vuln-desc { margin-bottom: 10px; }
                .vuln-explanation { 
                    font-size: 13px; color: #555; background: #eee; 
                    padding: 10px; border-radius: 3px; border-left: 2px solid #ccc;
                }

                .footer {
                    text-align: center; padding-top: 20px; border-top: 1px solid #ddd;
                    color: #7f8c8d; font-size: 12px; margin-top: 40px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Vulnerability Assessment Report</h1>
                    <p>Target: <span class="target">{{ target }}</span></p>
                    <p>Scan Date: {{ date }}</p>
                    <p>Endpoints Discovered: {{ stats.endpoints }} | Forms Discovered: {{ stats.forms }} | Total Findings: {{ stats.total }}</p>
                </div>

                <table class="summary-table">
                    <tr>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Info</th>
                        <th>Total</th>
                    </tr>
                    <tr>
                        <td class="val-Critical">{{ severity.Critical }}</td>
                        <td class="val-High">{{ severity.High }}</td>
                        <td class="val-Medium">{{ severity.Medium }}</td>
                        <td class="val-Low">{{ severity.Low }}</td>
                        <td class="val-Info">{{ severity.Info }}</td>
                        <td style="font-weight: bold;">{{ stats.total }}</td>
                    </tr>
                </table>

                {% for section_key, section_title in sections %}
                <div class="section">
                    <h2>{{ section_title }}</h2>
                    {% if results.get(section_key) %}
                        {% for item in results[section_key] %}
                        <div class="vuln-card vuln-{{ item.severity }}">
                            <span class="badge bg-{{ item.severity }}">{{ item.severity }}</span>
                            <div class="vuln-type">Vulnerability Type: {{ item.type }}</div>
                            <div class="vuln-desc"><strong>Description:</strong> {{ item.desc }}</div>
                            <div class="vuln-explanation"><strong>Explanation:</strong> {{ get_explanation(item.type) }}</div>
                        </div>
                        {% endfor %}
                    {% else %}
                        <p class="empty">No findings in this category.</p>
                    {% endif %}
                </div>
                {% endfor %}

                <div class="footer">
                    Generated by OmniScan v3.0 - Professional Security Assessment
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(html_template)
        
        # Calculate severity counts
        severity = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total = 0
        for key, items in self.results.items():
            if key in ["endpoints", "forms"]:
                continue
            for item in items:
                sev = item.get("severity", "Info")
                severity[sev] = severity.get(sev, 0) + 1
                total += 1
        
        stats = {
            "endpoints": len(self.results.get('endpoints', [])),
            "forms": len(self.results.get('forms', [])),
            "total": total
        }
        
        sections = [
            ("recon", "Reconnaissance"),
            ("dns_recon", "DNS Reconnaissance & Security"),
            ("header_audit", "Security Headers Audit"),
            ("info_disclosure", "Information Disclosure & Fingerprinting"),
            ("sqli", "SQL Injection"),
            ("xss", "Cross-Site Scripting (XSS)"),
            ("lfi", "Local File Inclusion (LFI)"),
            ("cors", "CORS Misconfigurations"),
            ("open_redirect", "Open Redirects"),
            ("wp", "WordPress Core Scan"),
            ("xmlrpc", "XML-RPC Exploitation"),
            ("wp_enum", "WordPress Enumeration"),
            ("iis_exploit", "IIS Server Exploitation"),
            ("elementor_exploit", "Elementor Plugin Exploitation"),
            ("wp_cve_exploit", "CVE Active Exploitation"),
            ("auto_exploit", "Exploitation Results"),
        ]
        
        html_out = template.render(
            target=self.target_url,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            results=self.results,
            stats=stats,
            severity=severity,
            sections=sections,
            get_explanation=get_explanation
        )
        
        html_filename = os.path.join(self.report_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_out)
            
        return html_filename

    def generate(self):
        # Save raw JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = os.path.join(self.report_dir, f"report_{timestamp}.json")
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=4)
            
        # Generate HTML report
        html_filename = self._generate_html(json_filename)
        
        return html_filename
