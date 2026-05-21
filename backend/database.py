"""
VaultX Database Models - SQLAlchemy async models
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text,
    ForeignKey, JSON, Enum as SQLEnum, func
)
import enum
import uuid
from datetime import datetime
from backend.config import settings


# ─── Engine & Session ────────────────────────────────────────────────────────

engine = create_async_engine(settings.DATABASE_URL, echo=settings.DEBUG, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


# ─── Enums ───────────────────────────────────────────────────────────────────

class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    VALIDATING = "validating"
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    ANALYZING = "analyzing"
    REPORTING = "reporting"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class OWASPCategory(str, enum.Enum):
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 – Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 – Cryptographic Failures"
    A03_INJECTION = "A03:2021 – Injection"
    A04_INSECURE_DESIGN = "A04:2021 – Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021 – Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 – Vulnerable and Outdated Components"
    A07_AUTHN_FAILURES = "A07:2021 – Identification and Authentication Failures"
    A08_SOFTWARE_DATA_INTEGRITY = "A08:2021 – Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021 – Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 – Server-Side Request Forgery"
    UNKNOWN = "Unknown"


# ─── Models ──────────────────────────────────────────────────────────────────

class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target = Column(String(255), nullable=False)
    scope = Column(JSON, nullable=False)          # {"domains": [...], "ip_ranges": [...], "excluded": [...]}
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, index=True)
    authorized = Column(Boolean, default=False)
    authorization_proof = Column(Text)            # User attestation or bug bounty program URL

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    # Configuration
    scan_config = Column(JSON, default={})        # Which tools to run, intensity, etc.
    ai_provider = Column(String(50), default="claude")

    # Aggregated results
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)

    # Error tracking
    error_message = Column(Text)
    phase_logs = Column(JSON, default=[])

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tool_results = relationship("ToolResult", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    # Core finding data
    title = Column(String(500), nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False, index=True)
    owasp_category = Column(SQLEnum(OWASPCategory), default=OWASPCategory.UNKNOWN)
    cvss_score = Column(Float, default=0.0)
    cvss_vector = Column(String(200))

    # Target info
    affected_endpoint = Column(String(1000))
    affected_parameter = Column(String(255))
    http_method = Column(String(10))

    # Evidence
    proof_of_concept = Column(Text)
    request_response = Column(JSON)               # Raw HTTP req/resp
    screenshot_path = Column(String(500))

    # AI-generated analysis
    root_cause = Column(Text)
    remediation_steps = Column(JSON)              # List of steps
    secure_code_example = Column(Text)
    false_positive_probability = Column(Float, default=0.0)
    validated = Column(Boolean, default=False)    # Confirmed via exploitation

    # Source
    discovered_by = Column(String(100))           # Which tool found it
    raw_output = Column(JSON)

    # Deduplication
    fingerprint = Column(String(64), index=True)  # SHA256 of key fields
    duplicate_of = Column(String(36), ForeignKey("findings.id"), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan = relationship("Scan", back_populates="findings")


class ToolResult(Base):
    __tablename__ = "tool_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)

    tool_name = Column(String(100), nullable=False)
    phase = Column(String(50))                    # recon | scanning | exploitation
    status = Column(String(50), default="pending")
    command = Column(Text)                        # Exact command run (for audit)
    output = Column(JSON)                         # Structured output
    raw_stdout = Column(Text)
    raw_stderr = Column(Text)
    exit_code = Column(Integer)
    duration_seconds = Column(Float)

    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    scan = relationship("Scan", back_populates="tool_results")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)

    format = Column(String(20))                   # pdf | json | markdown
    template = Column(String(50), default="hackerone")  # hackerone | standard | executive
    file_path = Column(String(500))
    file_size_bytes = Column(Integer)

    generated_at = Column(DateTime, default=datetime.utcnow)
    generated_by = Column(String(100), default="vaultx-report-agent")

    scan = relationship("Scan", back_populates="reports")
