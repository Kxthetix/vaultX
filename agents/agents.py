"""
VaultX AI Agents
────────────────
Agent 1: Vulnerability Analyzer   — deduplicate, classify, OWASP mapping
Agent 2: Risk Scoring Agent        — CVSS calculation + AI refinement
Agent 3: Root Cause & Fix Agent    — LLM-powered remediation
Agent 4: Report Generator Agent    — HackerOne-style professional reports

All agents are provider-agnostic (Claude / OpenAI / Ollama).
"""

import json
import hashlib
import asyncio
import logging
from typing import Any
from datetime import datetime

from backend.config import settings, get_ai_client

logger = logging.getLogger("vaultx.agents")


# ─── Prompt Templates ────────────────────────────────────────────────────────

VULNERABILITY_ANALYZER_PROMPT = """You are a senior penetration tester and vulnerability analyst at a top-tier security firm.

You will receive raw output from security scanning tools (Nmap, Nuclei, Nikto, ZAP, SQLmap, etc.).
Your job is to:
1. Extract all real vulnerabilities from the raw tool output
2. Deduplicate identical or near-identical findings
3. Classify each finding according to OWASP Top 10 2021
4. Assign preliminary severity (Critical/High/Medium/Low/Info)
5. Extract affected endpoints and parameters

Return ONLY valid JSON matching this exact schema:
{
  "vulnerabilities": [
    {
      "title": "string",
      "severity": "critical|high|medium|low|info",
      "owasp_category": "A01:2021|A02:2021|...|A10:2021|Unknown",
      "affected_endpoint": "string",
      "affected_parameter": "string or null",
      "http_method": "GET|POST|PUT|DELETE|null",
      "proof_of_concept": "string",
      "discovered_by": "tool name",
      "confidence": "confirmed|likely|possible",
      "raw_evidence": "key evidence snippet"
    }
  ],
  "duplicates_removed": number,
  "total_raw_findings": number,
  "analysis_notes": "string"
}

Raw tool output to analyze:
{raw_output}

Target: {target}
"""

RISK_SCORING_PROMPT = """You are a CVSS v3.1 expert and security risk analyst.

For each vulnerability provided, calculate a precise CVSS v3.1 score by evaluating:
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)
- Scope (Unchanged/Changed)
- Confidentiality Impact (None/Low/High)
- Integrity Impact (None/Low/High)
- Availability Impact (None/Low/High)

Also consider:
- Temporal metrics (exploit maturity, remediation level, report confidence)
- Environmental context (target type, data sensitivity)

Return ONLY valid JSON:
{
  "scored_vulnerabilities": [
    {
      "finding_id": "string",
      "cvss_score": number (0.0-10.0),
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "severity_confirmed": "critical|high|medium|low|info",
      "exploitability_score": number,
      "impact_score": number,
      "priority_rank": number,
      "risk_rationale": "Brief explanation of score"
    }
  ],
  "overall_risk_score": number (0-100),
  "risk_summary": "string"
}

Vulnerabilities to score:
{vulnerabilities}

Target context: {target_context}
"""

ROOT_CAUSE_PROMPT = """You are a world-class application security engineer specializing in vulnerability remediation.

For each vulnerability, provide:
1. Root cause analysis — why does this vulnerability exist?
2. Step-by-step remediation — actionable, specific fix steps
3. Secure code example — real code showing the fix (use the likely tech stack)
4. References — CVE IDs, CWE IDs, OWASP links where applicable

Return ONLY valid JSON:
{
  "remediation_analysis": [
    {
      "finding_id": "string",
      "root_cause": "Detailed technical explanation of why this vulnerability exists",
      "remediation_steps": [
        "Step 1: ...",
        "Step 2: ...",
        "Step 3: ..."
      ],
      "secure_code_example": "```language\\n...secure code...\\n```",
      "references": {
        "cve_ids": ["CVE-XXXX-XXXXX"],
        "cwe_ids": ["CWE-79"],
        "owasp_url": "https://owasp.org/...",
        "additional": ["..."]
      },
      "estimated_fix_time": "2-4 hours",
      "fix_complexity": "low|medium|high"
    }
  ]
}

Vulnerabilities requiring remediation:
{vulnerabilities}

Tech stack context: {tech_stack}
"""

REPORT_GENERATOR_PROMPT = """You are a professional bug bounty report writer who has submitted 500+ accepted reports on HackerOne and Bugcrowd.

Generate a professional, detailed security report section for the following vulnerability.
The report must be in HackerOne submission format — clear, concise, convincing.

Return ONLY valid JSON:
{
  "report_sections": [
    {
      "finding_id": "string",
      "title": "Concise, professional vulnerability title",
      "summary": "2-3 sentence executive summary",
      "vulnerability_detail": "Technical explanation (3-5 paragraphs)",
      "reproduction_steps": [
        "1. Navigate to https://target.com/login",
        "2. ...",
        "3. Observe the vulnerability"
      ],
      "impact": "What an attacker can achieve if exploiting this",
      "business_impact": "Business/data risk in non-technical terms",
      "supporting_evidence": "Description of evidence/PoC",
      "remediation_recommendation": "Concise fix recommendation",
      "bounty_estimate": "Based on platform guidelines",
      "weakness_type": "CWE category"
    }
  ],
  "executive_summary": "Overall assessment paragraph",
  "risk_rating": "Critical|High|Medium|Low",
  "engagement_summary": {
    "target": "string",
    "scan_date": "string",
    "total_findings": number,
    "critical": number,
    "high": number,
    "medium": number,
    "low": number,
    "tools_used": ["list"],
    "methodology": "string"
  }
}

Findings data:
{findings_data}

Scan metadata:
{scan_metadata}
"""


# ─── Base Agent Class ─────────────────────────────────────────────────────────

class BaseAgent:
    def __init__(self, name: str):
        self.name = name
        self.client = get_ai_client()
        self.provider = settings.AI_PROVIDER

    async def _call_llm(self, prompt: str, max_tokens: int = 4096) -> str:
        """Provider-agnostic LLM call with retry logic."""
        for attempt in range(3):
            try:
                if self.provider == "claude":
                    return await self._call_claude(prompt, max_tokens)
                elif self.provider == "openai":
                    return await self._call_openai(prompt, max_tokens)
                elif self.provider == "ollama":
                    return await self._call_ollama(prompt, max_tokens)
            except Exception as e:
                logger.warning(f"[{self.name}] LLM call attempt {attempt+1} failed: {e}")
                if attempt == 2:
                    raise
                await asyncio.sleep(2 ** attempt)

    async def _call_claude(self, prompt: str, max_tokens: int) -> str:
        import anthropic
        response = await self.client.messages.create(
            model=settings.CLAUDE_MODEL,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text

    async def _call_openai(self, prompt: str, max_tokens: int) -> str:
        response = await self.client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"}
        )
        return response.choices[0].message.content

    async def _call_ollama(self, prompt: str, max_tokens: int) -> str:
        import httpx
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{settings.OLLAMA_BASE_URL}/api/generate",
                json={
                    "model": settings.OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json"
                },
                timeout=120.0
            )
            return response.json()["response"]

    def _safe_parse_json(self, text: str) -> dict:
        """Safely parse JSON from LLM response, stripping markdown fences."""
        text = text.strip()
        if text.startswith("```json"):
            text = text[7:]
        if text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        return json.loads(text.strip())

    def _log(self, message: str):
        logger.info(f"[{self.name}] {message}")


# ─── Agent 1: Vulnerability Analyzer ─────────────────────────────────────────

class VulnerabilityAnalyzerAgent(BaseAgent):
    """
    Processes raw tool output → structured, deduplicated, OWASP-classified findings.
    """

    def __init__(self):
        super().__init__("VulnAnalyzer")

    def _fingerprint(self, vuln: dict) -> str:
        """Create deduplication fingerprint."""
        key = f"{vuln.get('title','')}{vuln.get('affected_endpoint','')}{vuln.get('owasp_category','')}".lower()
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    async def analyze(self, raw_tool_outputs: dict, target: str) -> dict:
        """
        Args:
            raw_tool_outputs: {"nmap": {...}, "nuclei": {...}, "nikto": {...}, ...}
            target: Target domain/IP
        Returns:
            Structured, deduplicated vulnerability list
        """
        self._log(f"Analyzing {len(raw_tool_outputs)} tool outputs for {target}")

        # Combine all raw outputs
        combined_raw = json.dumps(raw_tool_outputs, indent=2)

        prompt = VULNERABILITY_ANALYZER_PROMPT.format(
            raw_output=combined_raw[:12000],  # Token limit guard
            target=target
        )

        response_text = await self._call_llm(prompt, max_tokens=4096)
        result = self._safe_parse_json(response_text)

        # Add fingerprints for deduplication
        seen_fingerprints = set()
        unique_vulns = []
        for vuln in result.get("vulnerabilities", []):
            fp = self._fingerprint(vuln)
            if fp not in seen_fingerprints:
                seen_fingerprints.add(fp)
                vuln["fingerprint"] = fp
                vuln["id"] = hashlib.md5(fp.encode()).hexdigest()[:8]
                unique_vulns.append(vuln)

        result["vulnerabilities"] = unique_vulns
        self._log(f"Found {len(unique_vulns)} unique vulnerabilities")
        return result


# ─── Agent 2: Risk Scoring Agent ─────────────────────────────────────────────

class RiskScoringAgent(BaseAgent):
    """
    Calculates CVSS v3.1 scores and prioritizes vulnerabilities.
    """

    SEVERITY_THRESHOLDS = {
        "critical": (9.0, 10.0),
        "high": (7.0, 8.9),
        "medium": (4.0, 6.9),
        "low": (0.1, 3.9),
        "info": (0.0, 0.0)
    }

    def __init__(self):
        super().__init__("RiskScorer")

    def _rule_based_score(self, vuln: dict) -> float:
        """Quick rule-based CVSS estimate before AI refinement."""
        severity = vuln.get("severity", "info").lower()
        base_scores = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
        score = base_scores.get(severity, 0.0)

        # Adjust for network-reachable
        if vuln.get("http_method") in ["GET", "POST", "PUT", "DELETE"]:
            score = min(10.0, score + 0.5)

        # Confirmed findings score higher
        if vuln.get("confidence") == "confirmed":
            score = min(10.0, score + 0.5)

        return round(score, 1)

    async def score(self, vulnerabilities: list, target_context: str = "") -> dict:
        self._log(f"Scoring {len(vulnerabilities)} vulnerabilities")

        # Apply rule-based baseline scores first
        for vuln in vulnerabilities:
            vuln["preliminary_cvss"] = self._rule_based_score(vuln)

        prompt = RISK_SCORING_PROMPT.format(
            vulnerabilities=json.dumps(vulnerabilities[:30], indent=2),  # Batch limit
            target_context=target_context
        )

        response_text = await self._call_llm(prompt, max_tokens=3000)
        result = self._safe_parse_json(response_text)

        # Build lookup map
        score_map = {item["finding_id"]: item for item in result.get("scored_vulnerabilities", [])}

        # Merge scores back into vulnerabilities
        for vuln in vulnerabilities:
            vid = vuln.get("id", "")
            if vid in score_map:
                vuln.update(score_map[vid])
            else:
                vuln["cvss_score"] = vuln.get("preliminary_cvss", 0.0)

        self._log(f"Overall risk score: {result.get('overall_risk_score', 0)}")
        return {
            "vulnerabilities": vulnerabilities,
            "overall_risk_score": result.get("overall_risk_score", 0),
            "risk_summary": result.get("risk_summary", "")
        }


# ─── Agent 3: Root Cause & Fix Agent ─────────────────────────────────────────

class RootCauseFixAgent(BaseAgent):
    """
    Uses LLM to generate root cause analysis and remediation for each vulnerability.
    """

    def __init__(self):
        super().__init__("RemediationAgent")

    async def analyze(self, vulnerabilities: list, tech_stack: str = "Unknown") -> dict:
        self._log(f"Generating remediation for {len(vulnerabilities)} vulnerabilities")

        # Process in batches of 5 to stay within token limits
        all_remediation = []
        batch_size = 5

        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i + batch_size]
            self._log(f"Processing remediation batch {i//batch_size + 1}")

            prompt = ROOT_CAUSE_PROMPT.format(
                vulnerabilities=json.dumps(batch, indent=2),
                tech_stack=tech_stack
            )

            response_text = await self._call_llm(prompt, max_tokens=4096)
            result = self._safe_parse_json(response_text)
            all_remediation.extend(result.get("remediation_analysis", []))

        # Merge back
        remediation_map = {item["finding_id"]: item for item in all_remediation}

        for vuln in vulnerabilities:
            vid = vuln.get("id", "")
            if vid in remediation_map:
                r = remediation_map[vid]
                vuln["root_cause"] = r.get("root_cause", "")
                vuln["remediation_steps"] = r.get("remediation_steps", [])
                vuln["secure_code_example"] = r.get("secure_code_example", "")
                vuln["references"] = r.get("references", {})
                vuln["fix_complexity"] = r.get("fix_complexity", "medium")

        return {"vulnerabilities": vulnerabilities}


# ─── Agent 4: Report Generator Agent ─────────────────────────────────────────

class ReportGeneratorAgent(BaseAgent):
    """
    Generates professional HackerOne-style bug bounty reports.
    """

    def __init__(self):
        super().__init__("ReportAgent")

    async def generate(self, findings: list, scan_metadata: dict) -> dict:
        self._log(f"Generating report for {len(findings)} findings")

        prompt = REPORT_GENERATOR_PROMPT.format(
            findings_data=json.dumps(findings[:20], indent=2),
            scan_metadata=json.dumps(scan_metadata, indent=2)
        )

        response_text = await self._call_llm(prompt, max_tokens=6000)
        result = self._safe_parse_json(response_text)

        result["generated_at"] = datetime.utcnow().isoformat()
        result["generated_by"] = f"VaultX ReportAgent ({settings.AI_PROVIDER})"

        self._log("Report generated successfully")
        return result

    async def export_pdf(self, report_data: dict, output_path: str) -> str:
        """Export report to PDF using WeasyPrint."""
        from weasyprint import HTML
        import jinja2

        # Load HTML template
        template_loader = jinja2.FileSystemLoader(settings.PDF_TEMPLATE_DIR)
        env = jinja2.Environment(loader=template_loader)
        template = env.get_template("report.html.j2")

        html_content = template.render(**report_data)
        HTML(string=html_content).write_pdf(output_path)

        self._log(f"PDF exported to {output_path}")
        return output_path


# ─── Agent Orchestrator ────────────────────────────────────────────────────────

class AgentOrchestrator:
    """
    Coordinates all 4 agents in the analysis pipeline.
    """

    def __init__(self):
        self.analyzer = VulnerabilityAnalyzerAgent()
        self.scorer = RiskScoringAgent()
        self.remediator = RootCauseFixAgent()
        self.reporter = ReportGeneratorAgent()

    async def run_full_pipeline(
        self,
        raw_tool_outputs: dict,
        target: str,
        tech_stack: str = "Unknown",
        scan_metadata: dict = None
    ) -> dict:
        """
        Run all 4 agents sequentially, passing output between stages.
        """
        logger.info(f"🤖 Starting AI agent pipeline for {target}")

        # Stage 1: Analyze
        logger.info("Stage 1/4: Vulnerability Analysis")
        analysis = await self.analyzer.analyze(raw_tool_outputs, target)
        vulnerabilities = analysis["vulnerabilities"]

        if not vulnerabilities:
            logger.warning("No vulnerabilities found in tool outputs")
            return {"vulnerabilities": [], "report": {}, "overall_risk_score": 0}

        # Stage 2: Score
        logger.info("Stage 2/4: Risk Scoring")
        scored = await self.scorer.score(vulnerabilities, target_context=target)
        vulnerabilities = scored["vulnerabilities"]

        # Stage 3: Remediate
        logger.info("Stage 3/4: Root Cause & Remediation")
        remediated = await self.remediator.analyze(vulnerabilities, tech_stack)
        vulnerabilities = remediated["vulnerabilities"]

        # Stage 4: Report
        logger.info("Stage 4/4: Report Generation")
        report = await self.reporter.generate(
            vulnerabilities,
            scan_metadata or {"target": target, "scan_date": datetime.utcnow().isoformat()}
        )

        logger.info("✅ AI agent pipeline complete")
        return {
            "vulnerabilities": vulnerabilities,
            "report": report,
            "overall_risk_score": scored.get("overall_risk_score", 0),
            "risk_summary": scored.get("risk_summary", "")
        }
