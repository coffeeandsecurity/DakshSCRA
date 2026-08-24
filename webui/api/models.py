from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, func

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
    project_key = Column(String(96), nullable=False, default="default", index=True)
    project_name = Column(String(255), nullable=False, default="Default")

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


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_admin = Column(Boolean, nullable=False, default=False)
    # True whenever the current password was assigned by someone/something
    # else (initial admin bootstrap, an admin creating the account, or an
    # admin resetting the password) rather than chosen by the user - forces
    # a change on next login until they pick their own.
    must_change_password = Column(Boolean, nullable=False, default=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    last_login_at = Column(DateTime(timezone=True), nullable=True)


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    last_seen_at = Column(DateTime(timezone=True), nullable=True)
