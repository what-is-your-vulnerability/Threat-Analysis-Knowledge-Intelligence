"""TAKI 진단 엔진. 서버처럼 엔진을 가져다 쓰는 쪽은 여기와 taki.service만 import한다."""

from importlib.metadata import version

from taki.adapters.repo.local import ForbiddenPathError, check_allowed
from taki.config import AgentConfig, ConfigError, load_config
from taki.core.orchestrator import RunResult, run_scan
from taki.llm.gateway import BudgetExceeded, LlmCallError, LlmFormatError, SecretLeft
from taki.schemas.models import RunMode, SecurityRule

__version__ = version("taki")

__all__ = [
    "AgentConfig",
    "BudgetExceeded",
    "ConfigError",
    "ForbiddenPathError",
    "LlmCallError",
    "LlmFormatError",
    "RunMode",
    "RunResult",
    "SecretLeft",
    "SecurityRule",
    "__version__",
    "check_allowed",
    "load_config",
    "run_scan",
]
