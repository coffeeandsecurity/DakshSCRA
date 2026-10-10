from pydantic import BaseModel, Field, field_validator, model_validator
from typing import Any, Dict, Optional, List, Literal


class ScanOptions(BaseModel):
    estimate_assumptions: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('estimate_assumptions')
    @classmethod
    def validate_estimate_assumptions(cls, value):
        from core.effort import validate_assumptions
        validate_assumptions(value)
        return value

    exclude_checks: List[str] = Field(default_factory=list, max_length=64)
    exclude_paths: List[str] = Field(default_factory=list, max_length=100)
    exclude_types: List[str] = Field(default_factory=list, max_length=100)
    exclude_keywords: List[str] = Field(default_factory=list, max_length=100)
    recon_strict: bool = False
    baseline_mode: Literal['default', 'disabled', 'custom'] = 'default'
    baseline_file: Optional[str] = None
    review_config: Optional[str] = None
    state_mode: Literal['default', 'enabled', 'disabled'] = 'default'

    @field_validator('exclude_checks', 'exclude_paths', 'exclude_types', 'exclude_keywords')
    @classmethod
    def clean_exclusions(cls, value, info):
        cleaned = list(dict.fromkeys(item.strip() for item in value if item.strip()))
        if any(len(item) > 512 or '\x00' in item or '\n' in item or '\r' in item for item in cleaned):
            raise ValueError('Each exclusion must be a single line of at most 512 characters')
        if info.field_name == 'exclude_checks':
            from core.scan_catalog import CHECK_IDS
            if set(cleaned) - CHECK_IDS:
                raise ValueError('Unknown check class')
        return cleaned


class ScanCreate(ScanOptions):
    custom_rdl: List[str] = Field(default_factory=list, max_length=8)
    rdl_engine: Literal["v1", "v2", "both"] = "both"
    rules: str = Field(default="php")
    target_dir: str
    project_name: Optional[str] = None
    file_types: Optional[str] = None
    report_format: str = Field(default="web")
    verbosity: int = Field(default=1, ge=1, le=3)
    recon: bool = True
    estimate: bool = False
    analysis: bool = True
    loc: bool = True

    @model_validator(mode='after')
    def validate_modes(self):
        if self.recon_strict and not self.recon:
            raise ValueError('Strict reconnaissance requires reconnaissance')
        if self.baseline_mode == 'custom' and not (self.baseline_file or '').strip():
            raise ValueError('Select a baseline JSON file for custom baseline mode')
        return self


class ScanSummary(BaseModel):
    run_uuid: str
    project_key: str
    project_name: str
    status: str
    rules: str
    target_dir: str
    created_at: Optional[str] = None
    duration_sec: Optional[float] = None
    data_removed: bool = False
    data_removed_at: Optional[str] = None


class ScanDetails(ScanSummary, ScanOptions):
    custom_rdl: List[str] = Field(default_factory=list)
    rdl_engine: Literal["v1", "v2", "both"] = "v1"
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
    queued_scans: int
    failed_scans: int
    success_scans: int = 0
    stopped_scans: int = 0
    stopping_scans: int = 0
    data_removed_scans: int = 0
    latest_scan_at: Optional[str] = None
    latest_run_uuid: Optional[str] = None


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
    max_files_per_platform: int = Field(default=0, ge=0)
    max_functions_per_platform: int = Field(default=0, ge=0)


class StateManagementSettings(BaseModel):
    enabled: bool = False
    resume_mode: str = "manual"
    persist_after_seconds: int = 300
    persist_interval_seconds: int = 30
    cleanup_on_success: bool = False


class EstimationSettings(BaseModel):
    assumptions: Dict[str, Any] = Field(default_factory=dict)

    @field_validator('assumptions')
    @classmethod
    def validate_rates(cls, value):
        from core.effort import validate_assumptions
        return validate_assumptions(value)


class EffortPlanRequest(BaseModel):
    mode: Literal['assisted', 'targeted', 'manual', 'ai'] = 'assisted'
    domains: Optional[List[str]] = Field(default=None, max_length=11)
    assumptions: Dict[str, Any] = Field(default_factory=dict)
    calibration: List[Dict[str, Any]] = Field(default_factory=list, max_length=1000)

    @field_validator('domains')
    @classmethod
    def validate_domains(cls, value):
        from core.effort import DOMAINS
        if value is not None and set(value) - {key for key, _ in DOMAINS}:
            raise ValueError('Unknown review domain')
        return list(dict.fromkeys(value)) if value is not None else None

    @field_validator('assumptions')
    @classmethod
    def validate_rates(cls, value):
        from core.effort import validate_assumptions
        validate_assumptions(value)
        return value


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
    shortcuts: List[FsEntry] = Field(default_factory=list)


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    is_admin: bool
    must_change_password: bool = False
    created_at: Optional[str] = None
    last_login_at: Optional[str] = None


class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=8)
    is_admin: bool = False


class ChangePasswordRequest(BaseModel):
    new_password: str = Field(min_length=8)


class SelfChangePasswordRequest(BaseModel):
    current_password: Optional[str] = None
    new_password: str = Field(min_length=8)
    new_username: Optional[str] = None


class BootstrapInfo(BaseModel):
    default_username: str
    default_credentials_pending: bool
    default_password: Optional[str] = None
