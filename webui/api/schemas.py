from pydantic import BaseModel, Field
from typing import Any, Dict, Optional, List


class ScanCreate(BaseModel):
    rules: str = Field(default="php")
    target_dir: str
    project_name: Optional[str] = None
    file_types: Optional[str] = None
    report_format: str = Field(default="html")
    verbosity: int = Field(default=1, ge=1, le=3)
    recon: bool = False
    estimate: bool = False
    analysis: bool = True
    loc: bool = False


class ScanSummary(BaseModel):
    run_uuid: str
    project_key: str
    project_name: str
    status: str
    rules: str
    target_dir: str
    created_at: Optional[str] = None
    duration_sec: Optional[float] = None


class ScanDetails(ScanSummary):
    file_types: Optional[str] = None
    report_format: str
    verbosity: int
    recon: bool
    estimate: bool
    analysis: bool
    loc: bool
    command: str
    return_code: Optional[int] = None
    task_id: Optional[str] = None
    artifacts: List[str] = []


class ProjectSummary(BaseModel):
    project_key: str
    project_name: str
    target_dir: str
    rules: str
    total_scans: int
    running_scans: int
    failed_scans: int
    latest_scan_at: Optional[str] = None


class DashboardMetrics(BaseModel):
    total_projects: int
    total_scans: int
    running_scans: int
    queued_scans: int
    failed_scans: int
    success_scans: int
    success_rate: float
    avg_duration_sec: float
    recent_daily: List[dict]


class ArtifactIndex(BaseModel):
    report_html: Optional[str] = None
    xref_html: Optional[str] = None
    other_html: List[str] = []
    json_files: List[str] = []
    logs: List[str] = []
    pdf_files: List[str] = []
    all_artifacts: List[str] = []

class ToolInfo(BaseModel):
    tool_name: str = ""
    release: str = ""


class ProjectSettings(BaseModel):
    title: str = ""
    subtitle: str = ""


class DisplaySettings(BaseModel):
    timezone: str = ""


class AnalysisSettings(BaseModel):
    run_by_default: bool = True
    include_frameworks: bool = True
    report_theme: str = "hacker_mode"
    max_files_per_platform: int = 300
    max_functions_per_platform: int = 1500


class StateManagementSettings(BaseModel):
    enabled: bool = False
    resume_mode: str = "manual"
    persist_after_seconds: int = 300
    persist_interval_seconds: int = 30
    cleanup_on_success: bool = False


class EstimationSettings(BaseModel):
    efficiency_factor: int = 10
    buffer: int = 2


class SettingsData(BaseModel):
    tool_info: ToolInfo = ToolInfo()
    project: ProjectSettings = ProjectSettings()
    display: DisplaySettings = DisplaySettings()
    analysis: AnalysisSettings = AnalysisSettings()
    state_management: StateManagementSettings = StateManagementSettings()
    estimation: EstimationSettings = EstimationSettings()


class FsEntry(BaseModel):
    name: str
    path: str


class FsListResponse(BaseModel):
    current: str
    parent: Optional[str]
    roots: List[str]
    directories: List[FsEntry]
