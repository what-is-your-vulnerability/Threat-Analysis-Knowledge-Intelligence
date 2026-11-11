"""taki-server가 쓰는 엔진 공개 API(taki, taki.service)가 그대로 있는지 지킨다. 바꾸면 서버 저장소도 함께 고친다."""

import taki
import taki.service

SERVER_NAMES = {
    "AgentConfig", "BudgetExceeded", "ConfigError", "ForbiddenPathError", "LlmCallError", "LlmFormatError", "RunMode",
    "RunResult", "SecretLeft", "SecurityRule", "__version__", "check_allowed", "load_config", "run_scan",
}


def test_public_api_kept():
    assert SERVER_NAMES <= set(taki.__all__)
    assert all(hasattr(taki, name) for name in SERVER_NAMES)


def test_service_api_kept():
    assert callable(taki.service.list_entrypoints) and callable(taki.service.derive_project_rules)
