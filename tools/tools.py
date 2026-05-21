"""
VaultX Tool Integration Layer
──────────────────────────────
Executes real security tools via subprocess inside Docker containers.
Each tool returns structured JSON. All commands are logged for audit.

Tools:
  Recon:       Amass, Subfinder, Nmap, WhatWeb
  Scanning:    Nuclei, OWASP ZAP, Nikto
  Exploitation: SQLmap, Metasploit (safe mode)
"""

import asyncio
import json
import subprocess
import shlex
import logging
import tempfile
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Optional

from config import settings

logger = logging.getLogger("vaultx.tools")


# ─── Base Tool Runner ─────────────────────────────────────────────────────────

class ToolRunner:
    """Base class for all tool integrations."""

    def __init__(self, name: str, binary: str):
        self.name = name
        self.binary = binary
        self.timeout = settings.SCAN_TIMEOUT_SECONDS

    async def _run(self, args: list, timeout: int = None) -> dict:
        """
        Execute a command asynchronously, return structured result.
        All commands are logged for audit trail.
        """
        cmd = [self.binary] + args
        cmd_str = " ".join(shlex.quote(a) for a in cmd)
        logger.info(f"[{self.name}] EXECUTING: {cmd_str}")

        start_time = datetime.utcnow()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout or self.timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                logger.error(f"[{self.name}] Timed out after {timeout}s")
                return self._result(cmd_str, "", "TIMEOUT", -1, start_time, error="timeout")

            duration = (datetime.utcnow() - start_time).total_seconds()
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            logger.info(f"[{self.name}] Completed in {duration:.1f}s, exit={proc.returncode}")

            return self._result(
                cmd_str, stdout_str, stderr_str,
                proc.returncode, start_time, duration=duration
            )

        except FileNotFoundError:
            logger.error(f"[{self.name}] Binary not found: {self.binary}")
            return self._result(cmd_str, "", "", -1, start_time, error=f"binary_not_found:{self.binary}")

        except Exception as e:
            logger.error(f"[{self.name}] Unexpected error: {e}")
            return self._result(cmd_str, "", str(e), -1, start_time, error=str(e))

    def _result(self, command: str, stdout: str, stderr: str,
                exit_code: int, started_at: datetime,
                duration: float = 0, error: str = None) -> dict:
        return {
            "tool": self.name,
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "duration_seconds": duration,
            "started_at": started_at.isoformat(),
            "error": error,
            "success": exit_code == 0 and error is None
        }

    def _validate_target(self, target: str) -> bool:
        """Basic target validation — must be a domain or IP, not localhost/internal."""
        import ipaddress
        import re

        # Block internal ranges
        blocked = ["localhost", "127.", "192.168.", "10.", "172.16.", "0.0.0.0", "::1"]
        for b in blocked:
            if b in target.lower():
                raise ValueError(f"Target '{target}' is in blocked range (internal network)")

        # Must look like a domain or IP
        domain_re = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]{1,253}[a-zA-Z0-9]$')
        ip_re = re.compile(r'^\d{1,3}(\.\d{1,3}){3}(/\d{1,2})?$')

        if not (domain_re.match(target) or ip_re.match(target)):
            raise ValueError(f"Target '{target}' does not appear to be a valid domain or IP")

        return True


# ─── Recon Tools ─────────────────────────────────────────────────────────────

class NmapRunner(ToolRunner):
    """
    Nmap - Network port scanner and service detector.
    Runs in safe mode: no aggressive scripts, no DoS probes.
    """

    def __init__(self):
        super().__init__("nmap", settings.NMAP_PATH)

    async def scan(self, target: str, ports: str = "1-65535", options: str = "safe") -> dict:
        self._validate_target(target)

        if options == "quick":
            args = ["-sV", "-sC", "--top-ports", "1000", "-T3", "-oX", "-", target]
        elif options == "full":
            args = ["-sV", "-sC", "-p", ports, "-T3", "-A", "--script=safe", "-oX", "-", target]
        else:  # safe default
            args = ["-sV", "-p", "80,443,8080,8443,22,21,25,3306,5432,6379,27017", "-T3", "-oX", "-", target]

        result = await self._run(args, timeout=300)

        if result["success"] and result["stdout"]:
            result["parsed"] = self._parse_xml(result["stdout"])

        return result

    def _parse_xml(self, xml_output: str) -> dict:
        """Parse Nmap XML output into structured dict."""
        try:
            root = ET.fromstring(xml_output)
            hosts = []
            for host in root.findall("host"):
                host_data = {"status": "", "addresses": [], "ports": []}

                status = host.find("status")
                if status is not None:
                    host_data["status"] = status.get("state", "")

                for addr in host.findall("address"):
                    host_data["addresses"].append({
                        "addr": addr.get("addr"),
                        "addrtype": addr.get("addrtype")
                    })

                ports_elem = host.find("ports")
                if ports_elem:
                    for port in ports_elem.findall("port"):
                        port_data = {
                            "portid": port.get("portid"),
                            "protocol": port.get("protocol"),
                            "state": "",
                            "service": {}
                        }
                        state = port.find("state")
                        if state is not None:
                            port_data["state"] = state.get("state", "")

                        service = port.find("service")
                        if service is not None:
                            port_data["service"] = {
                                "name": service.get("name", ""),
                                "product": service.get("product", ""),
                                "version": service.get("version", ""),
                                "extrainfo": service.get("extrainfo", "")
                            }

                        script_outputs = {}
                        for script in port.findall("script"):
                            script_outputs[script.get("id")] = script.get("output")
                        if script_outputs:
                            port_data["scripts"] = script_outputs

                        host_data["ports"].append(port_data)

                hosts.append(host_data)
            return {"hosts": hosts}
        except ET.ParseError as e:
            logger.error(f"[nmap] XML parse error: {e}")
            return {"raw": xml_output, "parse_error": str(e)}


class AmassRunner(ToolRunner):
    """Amass - Subdomain enumeration."""

    def __init__(self):
        super().__init__("amass", settings.AMASS_PATH)

    async def enumerate(self, domain: str) -> dict:
        self._validate_target(domain)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name

        try:
            args = ["enum", "-passive", "-d", domain, "-json", output_file, "-timeout", "10"]
            result = await self._run(args, timeout=600)

            # Parse output file
            subdomains = []
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            subdomains.append({
                                "name": entry.get("name", ""),
                                "domain": entry.get("domain", ""),
                                "addresses": entry.get("addresses", []),
                                "tag": entry.get("tag", ""),
                                "source": entry.get("source", "")
                            })
                        except json.JSONDecodeError:
                            continue

            result["parsed"] = {"subdomains": subdomains, "count": len(subdomains)}
        finally:
            if os.path.exists(output_file):
                os.unlink(output_file)

        return result


class SubfinderRunner(ToolRunner):
    """Subfinder - Fast subdomain discovery."""

    def __init__(self):
        super().__init__("subfinder", settings.SUBFINDER_PATH)

    async def discover(self, domain: str) -> dict:
        self._validate_target(domain)
        args = ["-d", domain, "-oJ", "-silent", "-t", "100", "-timeout", "30"]
        result = await self._run(args, timeout=300)

        if result["success"]:
            subdomains = []
            for line in result["stdout"].splitlines():
                try:
                    entry = json.loads(line)
                    subdomains.append(entry)
                except json.JSONDecodeError:
                    if line.strip():
                        subdomains.append({"host": line.strip()})

            result["parsed"] = {"subdomains": subdomains, "count": len(subdomains)}

        return result


class WhatWebRunner(ToolRunner):
    """WhatWeb - Web technology fingerprinting."""

    def __init__(self):
        super().__init__("whatweb", settings.WHATWEB_PATH)

    async def fingerprint(self, url: str) -> dict:
        args = ["--log-json=-", "--quiet", "--aggression", "1", url]
        result = await self._run(args, timeout=60)

        if result["success"] and result["stdout"]:
            try:
                parsed = json.loads(result["stdout"])
                result["parsed"] = parsed
            except json.JSONDecodeError:
                result["parsed"] = {"raw": result["stdout"]}

        return result


# ─── Scanning Tools ───────────────────────────────────────────────────────────

class NucleiRunner(ToolRunner):
    """
    Nuclei - Template-based vulnerability scanner.
    Runs only safe, non-intrusive templates by default.
    """

    def __init__(self):
        super().__init__("nuclei", settings.NUCLEI_PATH)

    async def scan(self, target: str, severity: str = "medium,high,critical",
                   tags: str = None) -> dict:
        self._validate_target(target)

        args = [
            "-u", target,
            "-json",
            "-severity", severity,
            "-silent",
            "-no-interactsh",  # Disable OOB in safe mode
            "-rate-limit", "10",
            "-timeout", "5",
            "-retries", "1"
        ]

        if tags:
            args += ["-tags", tags]

        if settings.SAFE_MODE:
            # Exclude intrusive templates
            args += ["-exclude-tags", "dos,fuzz,blind"]

        result = await self._run(args, timeout=600)

        if result["stdout"]:
            findings = []
            for line in result["stdout"].splitlines():
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template_id": finding.get("template-id"),
                        "name": finding.get("info", {}).get("name"),
                        "severity": finding.get("info", {}).get("severity"),
                        "description": finding.get("info", {}).get("description"),
                        "matched_at": finding.get("matched-at"),
                        "host": finding.get("host"),
                        "ip": finding.get("ip"),
                        "matcher_name": finding.get("matcher-name"),
                        "curl_command": finding.get("curl-command"),
                        "tags": finding.get("info", {}).get("tags", []),
                        "reference": finding.get("info", {}).get("reference", []),
                        "cvss_metrics": finding.get("info", {}).get("classification", {})
                    })
                except json.JSONDecodeError:
                    continue

            result["parsed"] = {"findings": findings, "count": len(findings)}

        return result


class NiktoRunner(ToolRunner):
    """Nikto - Web server vulnerability scanner."""

    def __init__(self):
        super().__init__("nikto", settings.NIKTO_PATH)

    async def scan(self, target: str, port: int = 443) -> dict:
        self._validate_target(target)
        url = f"https://{target}" if port == 443 else f"http://{target}:{port}"

        args = [
            "-h", url,
            "-Format", "json",
            "-output", "/dev/stdout",
            "-Tuning", "0123456789",  # All check types
            "-maxtime", "300",
            "-no404"
        ]

        result = await self._run(args, timeout=400)

        if result["stdout"]:
            try:
                parsed = json.loads(result["stdout"])
                result["parsed"] = parsed
            except json.JSONDecodeError:
                # Parse text output as fallback
                vulns = self._parse_text_output(result["stdout"])
                result["parsed"] = {"vulnerabilities": vulns}

        return result

    def _parse_text_output(self, output: str) -> list:
        """Parse Nikto text output."""
        findings = []
        for line in output.splitlines():
            if "+ " in line and not line.startswith("+"):
                findings.append({"description": line.strip("+ ")})
        return findings


class ZAPRunner(ToolRunner):
    """
    OWASP ZAP - via REST API (ZAP running as daemon in Docker).
    """

    def __init__(self):
        super().__init__("owasp-zap", "zap-api")
        self.api_url = settings.ZAP_API_URL

    async def scan(self, target: str) -> dict:
        """Trigger ZAP active scan via API."""
        import httpx
        self._validate_target(target)

        async with httpx.AsyncClient(base_url=self.api_url) as client:
            # Spider first
            spider_resp = await client.get(
                "/JSON/spider/action/scan/",
                params={"url": f"https://{target}", "maxChildren": "10"}
            )
            spider_id = spider_resp.json().get("scan")

            # Wait for spider
            await asyncio.sleep(10)

            # Active scan
            scan_resp = await client.get(
                "/JSON/ascan/action/scan/",
                params={
                    "url": f"https://{target}",
                    "recurse": "true",
                    "inScopeOnly": "true"
                }
            )
            scan_id = scan_resp.json().get("scan")

            # Wait for completion
            for _ in range(60):
                status_resp = await client.get(
                    "/JSON/ascan/view/status/",
                    params={"scanId": scan_id}
                )
                status = int(status_resp.json().get("status", 0))
                if status >= 100:
                    break
                await asyncio.sleep(5)

            # Get alerts
            alerts_resp = await client.get(
                "/JSON/core/view/alerts/",
                params={"baseurl": f"https://{target}"}
            )
            alerts = alerts_resp.json().get("alerts", [])

        return {
            "tool": "owasp-zap",
            "success": True,
            "parsed": {"alerts": alerts, "count": len(alerts)},
            "duration_seconds": 0
        }


# ─── Exploitation Tools ───────────────────────────────────────────────────────

class SQLMapRunner(ToolRunner):
    """
    SQLmap - SQL injection detection and exploitation.
    Safe mode: detection only, no data extraction unless confirmed in scope.
    """

    def __init__(self):
        super().__init__("sqlmap", settings.SQLMAP_PATH)

    async def test(self, url: str, params: list = None, safe_mode: bool = True) -> dict:
        self._validate_target(url.split("/")[2] if "/" in url else url)

        args = [
            "-u", url,
            "--batch",
            "--json-output=/dev/stdout",
            "--level=2",
            "--risk=1",  # Low risk in safe mode
            "--threads=5",
            "--timeout=30",
            "--retries=2"
        ]

        if safe_mode or settings.SAFE_MODE:
            # Detection only - no exploitation
            args += ["--technique=BEUST", "--no-cast"]
        else:
            args += ["--technique=BEUSTQ"]

        if params:
            args += ["-p", ",".join(params)]

        result = await self._run(args, timeout=300)

        # Parse SQLmap JSON output
        if result["stdout"]:
            try:
                parsed = json.loads(result["stdout"])
                result["parsed"] = parsed
            except json.JSONDecodeError:
                vulnerabilities = self._parse_text(result["stdout"])
                result["parsed"] = {"vulnerabilities": vulnerabilities}

        return result

    def _parse_text(self, output: str) -> list:
        findings = []
        if "is vulnerable" in output.lower():
            lines = [l for l in output.splitlines() if "injectable" in l.lower() or "vulnerable" in l.lower()]
            for line in lines:
                findings.append({"description": line.strip(), "type": "sql_injection"})
        return findings


# ─── Tool Pipeline Orchestrator ───────────────────────────────────────────────

class ToolOrchestrator:
    """
    Orchestrates all tools across recon → scanning → exploitation phases.
    """

    def __init__(self):
        # Recon
        self.amass = AmassRunner()
        self.subfinder = SubfinderRunner()
        self.nmap = NmapRunner()
        self.whatweb = WhatWebRunner()
        # Scanning
        self.nuclei = NucleiRunner()
        self.nikto = NiktoRunner()
        self.zap = ZAPRunner()
        # Exploitation
        self.sqlmap = SQLMapRunner()

    async def run_recon(self, target: str, scope: dict) -> dict:
        """Phase 1: Reconnaissance."""
        logger.info(f"🔍 Starting recon phase for {target}")
        results = {}

        # Run recon tools concurrently
        tasks = {
            "subfinder": self.subfinder.discover(target),
            "nmap": self.nmap.scan(target),
            "whatweb": self.whatweb.fingerprint(f"https://{target}")
        }

        # Amass is slower, run separately
        amass_task = asyncio.create_task(self.amass.enumerate(target))
        concurrent_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for tool_name, result in zip(tasks.keys(), concurrent_results):
            if isinstance(result, Exception):
                logger.error(f"[recon] {tool_name} failed: {result}")
                results[tool_name] = {"error": str(result), "success": False}
            else:
                results[tool_name] = result

        try:
            results["amass"] = await asyncio.wait_for(amass_task, timeout=120)
        except asyncio.TimeoutError:
            results["amass"] = {"error": "timeout", "success": False}

        logger.info(f"✅ Recon complete. Tools run: {list(results.keys())}")
        return results

    async def run_scanning(self, target: str, recon_data: dict) -> dict:
        """Phase 2: Vulnerability Scanning."""
        logger.info(f"🔬 Starting scanning phase for {target}")
        results = {}

        # Nuclei scan
        try:
            results["nuclei"] = await self.nuclei.scan(target)
        except Exception as e:
            results["nuclei"] = {"error": str(e), "success": False}

        # Nikto scan
        try:
            results["nikto"] = await self.nikto.scan(target)
        except Exception as e:
            results["nikto"] = {"error": str(e), "success": False}

        # ZAP scan (if available)
        try:
            results["zap"] = await self.zap.scan(target)
        except Exception as e:
            logger.warning(f"ZAP scan skipped: {e}")
            results["zap"] = {"error": str(e), "success": False, "skipped": True}

        logger.info(f"✅ Scanning complete. Tools run: {list(results.keys())}")
        return results

    async def run_exploitation(self, target: str, scan_data: dict, safe: bool = True) -> dict:
        """Phase 3: Controlled exploitation to validate findings."""
        if not safe and not settings.SAFE_MODE:
            logger.warning("⚠️ Running in UNSAFE exploitation mode")

        logger.info(f"💥 Starting exploitation phase for {target} (safe={safe})")
        results = {}

        # Extract potential SQL injection targets from scan data
        sql_targets = self._extract_sql_targets(target, scan_data)

        for url in sql_targets[:5]:  # Limit to top 5 endpoints
            try:
                results[f"sqlmap_{url}"] = await self.sqlmap.test(url, safe_mode=safe)
            except Exception as e:
                results[f"sqlmap_{url}"] = {"error": str(e), "success": False}

        logger.info(f"✅ Exploitation phase complete")
        return results

    def _extract_sql_targets(self, target: str, scan_data: dict) -> list:
        """Extract URLs with parameters that might be SQLi candidates."""
        urls = [f"https://{target}/?id=1", f"https://{target}/search?q=test"]

        # Extract from ZAP alerts
        zap_data = scan_data.get("zap", {}).get("parsed", {})
        for alert in zap_data.get("alerts", []):
            if alert.get("pluginId") in ["40018", "40020"]:  # SQL injection plugin IDs
                url = alert.get("url", "")
                if url and url not in urls:
                    urls.append(url)

        return urls
