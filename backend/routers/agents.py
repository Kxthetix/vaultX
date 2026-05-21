"""VaultX AI Agents Router"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'agents'))
from agents import AgentOrchestrator, VulnerabilityAnalyzerAgent, RiskScoringAgent, RootCauseFixAgent, ReportGeneratorAgent

router = APIRouter()

class AgentRequest(BaseModel):
    raw_tool_outputs: dict
    target: str
    tech_stack: Optional[str] = "Unknown"
    scan_metadata: Optional[dict] = None

@router.post("/analyze")
async def run_full_pipeline(req: AgentRequest):
    orchestrator = AgentOrchestrator()
    result = await orchestrator.run_full_pipeline(
        raw_tool_outputs=req.raw_tool_outputs,
        target=req.target,
        tech_stack=req.tech_stack,
        scan_metadata=req.scan_metadata
    )
    return result

@router.post("/analyze/vuln")
async def run_vuln_analyzer(req: AgentRequest):
    agent = VulnerabilityAnalyzerAgent()
    return await agent.analyze(req.raw_tool_outputs, req.target)

@router.post("/analyze/score")
async def run_risk_scorer(req: AgentRequest):
    agent = RiskScoringAgent()
    vulns = req.raw_tool_outputs.get("vulnerabilities", [])
    return await agent.score(vulns, req.target)

@router.post("/analyze/remediate")
async def run_remediator(req: AgentRequest):
    agent = RootCauseFixAgent()
    vulns = req.raw_tool_outputs.get("vulnerabilities", [])
    return await agent.analyze(vulns, req.tech_stack or "Unknown")

@router.post("/analyze/report")
async def run_reporter(req: AgentRequest):
    agent = ReportGeneratorAgent()
    findings = req.raw_tool_outputs.get("findings", [])
    return await agent.generate(findings, req.scan_metadata or {"target": req.target})
