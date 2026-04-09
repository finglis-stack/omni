import json
import os
from datetime import datetime
from jinja2 import Template

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
            <title>OmniScan Report - {{ target }}</title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; 
                    background: #0f0f23; color: #e0e0e0; padding: 20px;
                    line-height: 1.6;
                }
                .container { 
                    max-width: 1200px; margin: 0 auto; 
                }
                .header {
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                    padding: 30px; border-radius: 12px; margin-bottom: 24px;
                    border: 1px solid #1e3a5f;
                }
                .header h1 { 
                    color: #00d4ff; font-size: 28px; margin-bottom: 10px;
                    text-shadow: 0 0 20px rgba(0, 212, 255, 0.3);
                }
                .header p { color: #8892b0; }
                .header .target { color: #64ffda; font-weight: bold; }

                .summary-grid {
                    display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                    gap: 12px; margin: 24px 0;
                }
                .summary-card {
                    background: #1a1a3e; padding: 16px; border-radius: 8px;
                    text-align: center; border: 1px solid #2a2a5e;
                    transition: transform 0.2s;
                }
                .summary-card:hover { transform: translateY(-2px); }
                .summary-card .count { font-size: 32px; font-weight: bold; }
                .summary-card .label { font-size: 12px; text-transform: uppercase; color: #8892b0; margin-top: 4px; }
                .sc-critical .count { color: #ff4757; }
                .sc-high .count { color: #ff6b35; }
                .sc-medium .count { color: #ffa502; }
                .sc-low .count { color: #ffd32a; }
                .sc-info .count { color: #45aaf2; }
                .sc-total .count { color: #00d4ff; }

                .section {
                    background: #1a1a2e; border-radius: 10px; padding: 24px;
                    margin-bottom: 20px; border: 1px solid #2a2a5e;
                }
                .section h2 {
                    color: #00d4ff; font-size: 20px; margin-bottom: 16px;
                    padding-bottom: 8px; border-bottom: 1px solid #2a2a5e;
                }
                .section .empty { color: #555; font-style: italic; }

                .vuln-card {
                    border-left: 4px solid;
                    padding: 12px 16px; margin-bottom: 12px;
                    border-radius: 0 6px 6px 0;
                    background: rgba(255,255,255,0.03);
                }
                .vuln-Critical { border-left-color: #ff4757; background: rgba(255,71,87,0.08); }
                .vuln-High { border-left-color: #ff6b35; background: rgba(255,107,53,0.08); }
                .vuln-Medium { border-left-color: #ffa502; background: rgba(255,165,2,0.08); }
                .vuln-Low { border-left-color: #ffd32a; background: rgba(255,211,42,0.06); }
                .vuln-Info { border-left-color: #45aaf2; background: rgba(69,170,242,0.06); }

                .badge {
                    display: inline-block; padding: 2px 10px; border-radius: 12px;
                    font-size: 11px; font-weight: 700; text-transform: uppercase;
                    margin-right: 8px;
                }
                .bg-Critical { background: #ff4757; color: #fff; }
                .bg-High { background: #ff6b35; color: #fff; }
                .bg-Medium { background: #ffa502; color: #1a1a2e; }
                .bg-Low { background: #ffd32a; color: #1a1a2e; }
                .bg-Info { background: #45aaf2; color: #fff; }

                .vuln-card .type { color: #8892b0; font-size: 12px; margin-top: 4px; }
                .vuln-card .desc { margin-top: 4px; word-break: break-all; }

                .footer {
                    text-align: center; padding: 20px; color: #555;
                    font-size: 13px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>⚡ OmniScan Vulnerability Report</h1>
                    <p>Target: <span class="target">{{ target }}</span></p>
                    <p>Scan Date: {{ date }}</p>
                    <p>Endpoints: {{ stats.endpoints }} | Forms: {{ stats.forms }} | Total Findings: {{ stats.total }}</p>
                </div>

                <div class="summary-grid">
                    <div class="summary-card sc-critical">
                        <div class="count">{{ severity.Critical }}</div>
                        <div class="label">Critical</div>
                    </div>
                    <div class="summary-card sc-high">
                        <div class="count">{{ severity.High }}</div>
                        <div class="label">High</div>
                    </div>
                    <div class="summary-card sc-medium">
                        <div class="count">{{ severity.Medium }}</div>
                        <div class="label">Medium</div>
                    </div>
                    <div class="summary-card sc-low">
                        <div class="count">{{ severity.Low }}</div>
                        <div class="label">Low</div>
                    </div>
                    <div class="summary-card sc-info">
                        <div class="count">{{ severity.Info }}</div>
                        <div class="label">Info</div>
                    </div>
                    <div class="summary-card sc-total">
                        <div class="count">{{ stats.total }}</div>
                        <div class="label">Total</div>
                    </div>
                </div>

                {% for section_key, section_title in sections %}
                <div class="section">
                    <h2>{{ section_title }}</h2>
                    {% if results[section_key] %}
                        {% for item in results[section_key] %}
                        <div class="vuln-card vuln-{{ item.severity }}">
                            <span class="badge bg-{{ item.severity }}">{{ item.severity }}</span>
                            <span class="desc">{{ item.desc }}</span>
                            <div class="type">[{{ item.type }}]</div>
                        </div>
                        {% endfor %}
                    {% else %}
                        <p class="empty">No findings in this category.</p>
                    {% endif %}
                </div>
                {% endfor %}

                <div class="footer">
                    Generated by OmniScan v2.0 — Advanced Web Vulnerability Scanner
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
            ("recon", "🔍 Reconnaissance"),
            ("header_audit", "🛡️ Security Headers Audit"),
            ("info_disclosure", "📡 Information Disclosure & Fingerprinting"),
            ("sqli", "💉 SQL Injection"),
            ("xss", "⚡ Cross-Site Scripting (XSS)"),
            ("lfi", "📂 Local File Inclusion (LFI)"),
            ("cors", "🌐 CORS Misconfigurations"),
            ("open_redirect", "↗️ Open Redirects"),
            ("wp", "🔧 WordPress Core Scan"),
            ("xmlrpc", "📡 XML-RPC Exploitation"),
            ("wp_enum", "🔎 WordPress Deep Enumeration"),
            ("xmlrpc_bruteforce", "🔑 XML-RPC Brute-Force Attack"),
            ("iis_exploit", "💥 IIS Server Exploitation"),
            ("elementor_exploit", "🧩 Elementor Plugin Exploitation"),
            ("wp_cve_exploit", "🔥 CVE Active Exploitation"),
            ("auto_exploit", "💀 Auto-Exploitation Results & Proofs"),
        ]
        
        html_out = template.render(
            target=self.target_url,
            date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            results=self.results,
            stats=stats,
            severity=severity,
            sections=sections
        )
        
        html_filename = os.path.join(self.report_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_out)
            
        return html_filename

    def generate(self):
        # Save raw JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_filename = os.path.join(self.report_dir, f"report_{timestamp}.json")
        with open(json_filename, 'w') as f:
            json.dump(self.results, f, indent=4)
            
        # Generate HTML report
        html_filename = self._generate_html(json_filename)
        
        return html_filename
