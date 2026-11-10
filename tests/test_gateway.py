import json

import pytest
from conftest import make_config
from pydantic import BaseModel

from agent.config import ConfigError, load_config
from agent.llm import masking
from agent.llm.gateway import BudgetExceeded, LlmCallError, LlmFormatError, LlmGateway, SecretLeft
from agent.llm.masking import mask_text
from agent.schemas.models import Budget


class Answer(BaseModel):
    value: int


def _gateway(fake, tmp_path, **overrides):
    return LlmGateway(make_config(fake, **overrides), tmp_path)


def _call(gw, content="hello", **kwargs):
    kwargs.setdefault("budget", Budget())
    return gw.complete("investigate", [{"role": "user", "content": content}], prompt_version="p_v1", **kwargs)


def test_missing_model_fails_before_any_request(fake, tmp_path):
    gw = _gateway(fake, tmp_path, models={"investigate": None})
    with pytest.raises(ConfigError):
        _call(gw)
    assert fake.requests == []


def test_default_config_has_no_model(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    assert all(v is None for v in load_config(None).models.values())


def test_env_overrides_base_url(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LLM_BASE_URL", "http://127.0.0.1:9/v1")
    assert load_config(None).base_url == "http://127.0.0.1:9/v1"


def test_masks_secret_keeps_operator():
    src = 'if (token === "sk-abc123def456ghi789") {'
    r = mask_text(src)
    assert "sk-abc" not in r.text and '=== "' in r.text and len(r.text) == len(src)


def test_masks_resident_number():
    r = mask_text("rrn = 900101-1234567;")
    assert "900101" not in r.text and r.replacements == 1


def test_mask_keeps_line_numbers():
    src = "a\n-----BEGIN RSA PRIVATE KEY-----\nabc\ndef\n-----END RSA PRIVATE KEY-----\nb\n"
    r = mask_text(src)
    assert "abc" not in r.text and r.text.count("\n") == src.count("\n") and r.text.startswith("a\n")


def test_masked_password_is_not_flagged_again():
    r = mask_text('password = "hunter2hunter2"')
    assert "hunter2" not in r.text and masking.find_secrets(r.text) == []


def test_residual_secret_blocks_send(fake, tmp_path, monkeypatch):
    monkeypatch.setattr(masking, "mask_text", lambda t: masking.MaskResult(t, 0))
    with pytest.raises(SecretLeft):
        _call(_gateway(fake, tmp_path), "key sk-abc123def456ghi789")
    assert fake.requests == []
    assert "sk-abc" not in (tmp_path / "manifest.jsonl").read_text()


def test_secret_is_masked_before_send(fake, tmp_path):
    fake.responses.append({"content": "ok"})
    _call(_gateway(fake, tmp_path), "key sk-abc123def456ghi789")
    sent = json.dumps(fake.requests)
    assert "sk-abc" not in sent
    assert "sk-abc" not in (tmp_path / "manifest.jsonl").read_text()


def test_retry_once_on_bad_json(fake, tmp_path):
    fake.responses += [{"content": "not json"}, {"content": '{"value": 3}'}]
    r = _call(_gateway(fake, tmp_path), schema=Answer)
    assert r.parsed == Answer(value=3) and len(fake.requests) == 2


def test_format_error_after_retry(fake, tmp_path):
    fake.responses += [{"content": "not json"}, {"content": '{"value": "x"}'}]
    with pytest.raises(LlmFormatError):
        _call(_gateway(fake, tmp_path), schema=Answer)
    assert len(fake.requests) == 2


def test_api_error_retries_then_raises(fake, tmp_path):
    fake.responses += [{"status": 429}, {"status": 429}]
    with pytest.raises(LlmCallError):
        _call(_gateway(fake, tmp_path))
    assert len(fake.requests) == 2
    assert json.loads((tmp_path / "manifest.jsonl").read_text().splitlines()[-1])["error"]


def test_over_input_budget_blocks_send(fake, tmp_path):
    with pytest.raises(BudgetExceeded):
        _call(_gateway(fake, tmp_path), "x" * 400, budget=Budget(max_input_tokens=100))
    assert fake.requests == []


def test_manifest_records_call(fake, tmp_path):
    fake.responses.append({"content": "ok"})
    r = _call(_gateway(fake, tmp_path), case_id="c1", sent_files=["A.java"])
    entry = json.loads((tmp_path / "manifest.jsonl").read_text().splitlines()[0])
    assert entry["manifest_id"] == r.manifest_id and entry["model"] == "fake-model"
    assert entry["prompt_version"] == "p_v1" and entry["sent_files"] == ["A.java"] and entry["case_id"] == "c1"
    assert entry["input_tokens"] == 10 and entry["output_tokens"] == 5


def test_tool_calls_are_returned(fake, tmp_path):
    fake.responses.append({"tool_calls": [{"name": "read_code", "arguments": {"path": "A.java"}}]})
    r = _call(_gateway(fake, tmp_path), tools=[{"type": "function", "function": {"name": "read_code"}}])
    assert r.tool_calls[0]["name"] == "read_code" and json.loads(r.tool_calls[0]["arguments"]) == {"path": "A.java"}
