"""
VaultX Scan Worker
Consumes scan jobs from RabbitMQ, runs tool pipeline, then AI agents.
"""
import asyncio, json, logging, os, sys
sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'agents'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'tools'))

import aio_pika
from datetime import datetime
from backend.config import settings
from backend.database import init_db, AsyncSessionLocal, Scan, ScanStatus, Finding, ToolResult

logger = logging.getLogger("vaultx.worker")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")

WORKER_TYPE = os.environ.get("WORKER_TYPE", "scan")


async def process_scan(scan_id: str):
    """Full scan pipeline: recon → scan → exploit → AI agents."""
    from tools import ToolOrchestrator
    from agents import AgentOrchestrator

    tool_orch = ToolOrchestrator()
    agent_orch = AgentOrchestrator()

    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        target = scan.target
        logger.info(f"Starting scan pipeline for {target} (scan_id={scan_id})")

        try:
            # Phase 1: Recon
            scan.status = ScanStatus.RECON
            scan.started_at = datetime.utcnow()
            await db.commit()
            recon_data = await tool_orch.run_recon(target, scan.scope)

            # Phase 2: Scanning
            scan.status = ScanStatus.SCANNING
            await db.commit()
            scan_data = await tool_orch.run_scanning(target, recon_data)

            # Phase 3: Exploitation (safe mode)
            scan.status = ScanStatus.EXPLOITING
            await db.commit()
            exploit_data = await tool_orch.run_exploitation(target, scan_data, safe=True)

            # Phase 4: AI Analysis
            scan.status = ScanStatus.ANALYZING
            await db.commit()
            all_raw = {**recon_data, **scan_data, **exploit_data}
            ai_results = await agent_orch.run_full_pipeline(
                raw_tool_outputs=all_raw,
                target=target,
                scan_metadata={"scan_id": scan_id, "target": target, "scan_date": datetime.utcnow().isoformat()}
            )

            # Save findings
            scan.status = ScanStatus.REPORTING
            await db.commit()
            vulns = ai_results.get("vulnerabilities", [])
            for v in vulns:
                finding = Finding(
                    scan_id=scan_id,
                    title=v.get("title", "Unknown"),
                    severity=v.get("severity_confirmed", v.get("severity", "info")),
                    owasp_category=v.get("owasp_category", "Unknown"),
                    cvss_score=v.get("cvss_score", 0.0),
                    cvss_vector=v.get("cvss_vector"),
                    affected_endpoint=v.get("affected_endpoint"),
                    affected_parameter=v.get("affected_parameter"),
                    proof_of_concept=v.get("proof_of_concept"),
                    root_cause=v.get("root_cause"),
                    remediation_steps=v.get("remediation_steps", []),
                    secure_code_example=v.get("secure_code_example"),
                    discovered_by=v.get("discovered_by"),
                    fingerprint=v.get("fingerprint", ""),
                    validated=v.get("confidence") == "confirmed",
                )
                db.add(finding)

            scan.total_findings = len(vulns)
            scan.critical_count = sum(1 for v in vulns if v.get("severity") == "critical")
            scan.high_count = sum(1 for v in vulns if v.get("severity") == "high")
            scan.medium_count = sum(1 for v in vulns if v.get("severity") == "medium")
            scan.low_count = sum(1 for v in vulns if v.get("severity") == "low")
            scan.risk_score = ai_results.get("overall_risk_score", 0)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            await db.commit()

            logger.info(f"✅ Scan {scan_id} completed — {len(vulns)} findings")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
            scan.status = ScanStatus.FAILED
            scan.error_message = str(e)
            await db.commit()


async def main():
    await init_db()
    logger.info(f"🔄 VaultX {WORKER_TYPE} worker starting...")

    try:
        conn = await aio_pika.connect_robust(settings.RABBITMQ_URL)
        channel = await conn.channel()
        await channel.set_qos(prefetch_count=3)
        queue = await channel.declare_queue(WORKER_TYPE == "scan" and "scans" or "agents", durable=True)

        async with queue.iterator() as q:
            async for message in q:
                async with message.process():
                    body = json.loads(message.body)
                    scan_id = body.get("scan_id")
                    if scan_id:
                        await process_scan(scan_id)
    except Exception as e:
        logger.error(f"Worker failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())
