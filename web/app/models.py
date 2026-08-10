from pydantic import BaseModel
from typing import Optional


class ScanMeta(BaseModel):
    scan_id: str
    filename: str
    state: str          # queued | running | done | error
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None
    llm_enabled: bool = False
    llm_provider: str = "none"
    llm_mode: str = "summarize"
    llm_model: str = ""
    assessment_enabled: bool = True


class ScanDetail(ScanMeta):
    bundle_id: Optional[str] = None
    bundle_executable: Optional[str] = None
    platform: Optional[str] = None
    is_swift: Optional[bool] = None
    is_universal: Optional[bool] = None
    architectures: Optional[list[str]] = None
    db_path: Optional[str] = None
    ipa_path: Optional[str] = None
    team_id: Optional[str] = None
    provisioning_profile: Optional[str] = None
    provisioning_expiry: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    class_count: Optional[int] = None
    function_count: Optional[int] = None
    string_count: Optional[int] = None
    entry_point_count: Optional[int] = None
    llm_finding_count: Optional[int] = None
    vulnerability_counts: Optional[dict] = None
    has_sarif: bool = False
    has_html: bool = False
    has_log: bool = False


class FunctionItem(BaseModel):
    function_name: str
    decompiled: Optional[str] = None


class FunctionPage(BaseModel):
    class_name: Optional[str]
    page: int
    size: int
    total: int
    items: list[FunctionItem]
    classes: list[str]


class StringItem(BaseModel):
    address: Optional[str]
    value: str
    segment: Optional[str]
    label: Optional[str]


class ResourceItem(BaseModel):
    resource_id: str
    value: str
    type: str


class LlmFinding(BaseModel):
    function_name: str
    class_name: Optional[str]
    mode: str
    finding: str
