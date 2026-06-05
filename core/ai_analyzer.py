"""
OmniScan AI Analyzer — OpenRouter LLM Integration
Analyzes scan results using AI to generate executive summaries,
attack narratives, remediation plans, and risk scoring.
"""
import json
import os
import aiohttp
from colorama import Fore, Style

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "deepseek/deepseek-chat-v3-0324"


class AIAnalyzer:
    def __init__(self, api_key=None, model=None):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self.model = model or DEFAULT_MODEL
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/finglis-stack/omni",
            "X-Title": "OmniScan Vulnerability Scanner",
        }

    async def _query(self, system_prompt, user_prompt, max_tokens=2048):
        """Send a query to OpenRouter and return the response text."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.4,
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(OPENROUTER_API_URL, headers=self.headers,
                                        json=payload, timeout=60) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data["choices"][0]["message"]["content"]
                    else:
                        error = await resp.text()
                        return f"[AI Error {resp.status}]: {error[:200]}"
        except Exception as e:
            return f"[AI Error]: {str(e)}"

    def _build_findings_summary(self, results):
        """Convert scan results dict into a compact text summary for the LLM."""
        lines = []
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

        for module, findings in results.items():
            if module in ("endpoints", "forms"):
                continue
            if not findings:
                continue
            for f in findings:
                sev = f.get("severity", "Info")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                lines.append(f"[{sev}] ({module}) {f.get('desc', f.get('type', 'unknown'))}")

        header = (
            f"Total findings: {sum(severity_counts.values())} | "
            f"Critical: {severity_counts['Critical']} | "
            f"High: {severity_counts['High']} | "
            f"Medium: {severity_counts['Medium']} | "
            f"Low: {severity_counts['Low']} | "
            f"Info: {severity_counts['Info']}"
        )
        return header + "\n\n" + "\n".join(lines[:80])  # Cap to avoid token overflow

    async def executive_summary(self, target_url, results):
        """Generate a professional executive summary of the scan."""
        system = (
            "You are a senior penetration tester writing an executive summary for a client. "
            "Be professional, concise, and impactful. Use markdown formatting. "
            "Include: overall risk level, key critical findings, business impact, and top 3 priorities. "
            "Write in a way that a non-technical CEO can understand."
        )
        user = (
            f"Target: {target_url}\n\n"
            f"Scan Results:\n{self._build_findings_summary(results)}"
        )
        return await self._query(system, user, max_tokens=1500)

    async def attack_narrative(self, target_url, results):
        """Generate a step-by-step attack narrative showing how an attacker would chain vulns."""
        system = (
            "You are a red team operator. Based on the vulnerability scan results, write a detailed "
            "attack narrative describing how a real attacker would chain these vulnerabilities together "
            "to achieve maximum impact. Structure it as numbered steps from initial reconnaissance to "
            "full compromise. Be specific — reference the actual findings. Use markdown formatting. "
            "Include: initial access vector, privilege escalation path, data exfiltration method, "
            "and persistence mechanisms."
        )
        user = (
            f"Target: {target_url}\n\n"
            f"Discovered vulnerabilities:\n{self._build_findings_summary(results)}"
        )
        return await self._query(system, user, max_tokens=2048)

    async def remediation_plan(self, target_url, results):
        """Generate prioritized remediation recommendations."""
        system = (
            "You are a cybersecurity consultant. Based on the scan results, generate a prioritized "
            "remediation plan. For each finding category, provide: the fix, estimated effort "
            "(quick win / moderate / significant), and the risk reduction impact. "
            "Order by priority (critical first). Use markdown with tables when appropriate."
        )
        user = (
            f"Target: {target_url}\n\n"
            f"Findings:\n{self._build_findings_summary(results)}"
        )
        return await self._query(system, user, max_tokens=2048)

    async def risk_score(self, target_url, results):
        """Calculate an AI-powered risk score with justification."""
        system = (
            "You are a risk assessment engine. Analyze the vulnerabilities and return a JSON object with:\n"
            '{"score": <0-100>, "grade": "<A/B/C/D/F>", "summary": "<one sentence>", '
            '"breakdown": {"infrastructure": <0-100>, "application": <0-100>, "data_exposure": <0-100>, "authentication": <0-100>}}\n'
            "Only return valid JSON, nothing else."
        )
        user = (
            f"Target: {target_url}\n\n"
            f"Findings:\n{self._build_findings_summary(results)}"
        )
        raw = await self._query(system, user, max_tokens=300)
        try:
            # Try to parse JSON from the response
            raw = raw.strip()
            if raw.startswith("```"):
                raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
            return json.loads(raw)
        except (json.JSONDecodeError, IndexError):
            return {"score": 0, "grade": "?", "summary": raw, "breakdown": {}}

    async def full_analysis(self, target_url, results):
        """Run all AI analyses and return a combined result dict."""
        import asyncio
        summary_task = asyncio.create_task(self.executive_summary(target_url, results))
        narrative_task = asyncio.create_task(self.attack_narrative(target_url, results))
        remediation_task = asyncio.create_task(self.remediation_plan(target_url, results))
        risk_task = asyncio.create_task(self.risk_score(target_url, results))

        summary, narrative, remediation, risk = await asyncio.gather(
            summary_task, narrative_task, remediation_task, risk_task
        )

        return {
            "executive_summary": summary,
            "attack_narrative": narrative,
            "remediation_plan": remediation,
            "risk_score": risk,
        }
