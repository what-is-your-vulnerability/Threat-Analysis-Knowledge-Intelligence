"""OpenAI 호환 주소를 흉내 내는 모의 LLM. 시험과 데모에서 실제 호출 없이 쓴다."""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _completion(item: dict) -> dict:
    message = {"role": "assistant", "content": item.get("content")}
    if item.get("tool_calls"):
        message["tool_calls"] = [
            {"id": f"call_{i}", "type": "function",
             "function": {"name": c["name"], "arguments": json.dumps(c.get("arguments", {}), ensure_ascii=False)}}
            for i, c in enumerate(item["tool_calls"])
        ]
    return {
        "id": "fake", "object": "chat.completion", "created": 0, "model": "fake",
        "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


class FakeLlm:
    """responses의 각 항목은 {content}, {tool_calls}, {status} 중 하나다.

    `match`가 있으면 요청 본문에 그 문자열이 있을 때마다 재사용하고, 없으면 순서대로 한 번씩 쓴다.
    """

    def __init__(self, responses: list[dict] | None = None, port: int = 0):
        self.responses = list(responses or [])
        self.requests: list[dict] = []
        self._port = port
        self._lock = threading.Lock()

    def _next(self, raw: str) -> dict:
        with self._lock:
            for item in self.responses:
                if "match" in item and item["match"] in raw:
                    return item
            for i, item in enumerate(self.responses):
                if "match" not in item:
                    return self.responses.pop(i)
        return {"status": 500}

    def __enter__(self):
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body_json = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
                fake.requests.append(body_json)
                item = fake._next(json.dumps(body_json, ensure_ascii=False))
                status = item.get("status", 200)
                body = _completion(item) if status == 200 else {"error": {"message": "fake", "type": "fake"}}
                data = json.dumps(body, ensure_ascii=False).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", self._port), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/v1"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["serve"])
    parser.add_argument("script")
    parser.add_argument("--port", type=int, default=0)  # 0이면 비어 있는 포트를 쓴다.
    args = parser.parse_args()
    with open(args.script, encoding="utf-8") as f, FakeLlm(json.load(f), port=args.port) as fake:
        print(fake.url, flush=True)
        threading.Event().wait()


if __name__ == "__main__":
    main()
