from sqlalchemy import Column, DateTime, Float, Integer, String, Text, func

from .database import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    project_key = Column(String(96), unique=True, nullable=False, index=True)
    project_name = Column(String(255), nullable=False)
    target_dir = Column(Text, nullable=False)
    rules = Column(String(255), nullable=False, default="php")

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    run_uuid = Column(String(64), unique=True, nullable=False, index=True)
    status = Column(String(32), nullable=False, default="queued", index=True)
    task_id = Column(String(128), nullable=True, index=True)
    project_key = Column(String(96), nullable=False, default="legacy", index=True)
    project_name = Column(String(255), nullable=False, default="Legacy")

    rules = Column(String(255), nullable=False)
    target_dir = Column(Text, nullable=False)
    file_types = Column(String(255), nullable=True)
    report_format = Column(String(64), nullable=False, default="html")
    verbosity = Column(Integer, nullable=False, default=1)
    recon = Column(String(5), nullable=False, default="false")
    estimate = Column(String(5), nullable=False, default="false")
    analysis = Column(String(5), nullable=False, default="true")
    loc = Column(String(5), nullable=False, default="false")

    command = Column(Text, nullable=False)
    return_code = Column(Integer, nullable=True)
    duration_sec = Column(Float, nullable=True)
    log_path = Column(Text, nullable=False)
    artifacts_json = Column(Text, nullable=False, default="[]")

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    ended_at = Column(DateTime(timezone=True), nullable=True)
