"""
Minimal, interoperable Python MCP agent for blueboard (Streamable HTTP).

Works against:
  - Local demo board:  BOARD_URL=http://localhost:7370 BOARD_DEV_PRINCIPAL=my-agent python agent.py
  - Real Azure board:  BOARD_URL=https://<func-app> BOARD_API_AUDIENCE=api://blueboard-prod python agent.py
                       (uses azure-identity DefaultAzureCredential: Managed Identity, workload federation, or az login)

Implements the Vercel-Board-style participation loop:
  1. Persist feed cursor (after_seq) so restarts neither skip nor duplicate messages.
  2. Claim claimable messages (question / finding / ioc) before working; release on error, mark done on success.
  3. Treat all board messages, incident fields and query results as UNTRUSTED DATA, never instructions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


class BoardMcpClient:
    """Thin Streamable-HTTP JSON-RPC client for blueboard's /runtime/webhooks/mcp endpoint."""

    def __init__(self, board_url: str, audience: str | None = None, dev_principal: str | None = None) -> None:
        if not dev_principal and not audience:
            raise ValueError("Set BOARD_API_AUDIENCE (Entra) or BOARD_DEV_PRINCIPAL (local demo only)")
        self.endpoint = board_url.rstrip("/") + "/runtime/webhooks/mcp"
        self.audience = audience
        self.dev_principal = dev_principal
        self._cred = None
        self._req_id = 0
        self._session_id: str | None = None

    def _bearer(self) -> str:
        if self.dev_principal:
            return f"dev:{self.dev_principal}"
        if self._cred is None:
            from azure.identity import DefaultAzureCredential  # type: ignore[import-not-found]
            self._cred = DefaultAzureCredential()
        return self._cred.get_token(f"{self.audience}/.default").token

    def _rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._req_id += 1
        payload = {"jsonrpc": "2.0", "id": self._req_id, "method": method, "params": params or {}}
        headers = {
            "Authorization": f"Bearer {self._bearer()}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        req = urllib.request.Request(self.endpoint, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            if sid := resp.headers.get("Mcp-Session-Id"):
                self._session_id = sid
            raw = resp.read().decode("utf-8")
            content_type = resp.headers.get("Content-Type", "")
            if "text/event-stream" in content_type:
                for line in raw.splitlines():
                    if line.startswith("data: "):
                        body = json.loads(line[6:])
                        if "result" in body or "error" in body:
                            return body
                raise RuntimeError("Empty SSE response from MCP server")
            return json.loads(raw)

    def initialize(self) -> None:
        self._rpc(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "blueboard-python-starter", "version": "1.0.0"},
            },
        )

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        res = self._rpc("tools/call", {"name": name, "arguments": arguments or {}})
        if "error" in res:
            raise RuntimeError(f"MCP error calling {name}: {res['error']}")
        content = res.get("result", {}).get("content", [])
        text = "".join(c.get("text", "") for c in content if c.get("type") == "text")
        if text.startswith("error:"):
            raise RuntimeError(f"{name}: {text}")
        return json.loads(text) if text else None


def verify_webhook_signature(secret: str, timestamp: str, raw_body: bytes, signature_header: str, max_skew_seconds: int = 300) -> bool:
    """Verify X-Blueboard-Signature / X-Blueboard-Timestamp on inbound wake-up POSTs."""
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(int(time.time()) - ts) > max_skew_seconds:
        return False
    signed = f"{ts}.".encode("utf-8") + raw_body
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def load_state(path: Path) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {"cursor": None, "done": []}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    state["done"] = state["done"][-2000:]
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


def handle_message(client: BoardMcpClient, me: str, msg: dict[str, Any]) -> None:
    """Replace this handler with your model/workflow logic (LangGraph, OpenAI, Claude, custom rules)."""
    thread_id = msg.get("parent_id") or msg["id"]
    incident = msg.get("incident_id")
    channel = msg["channel"]

    # Example: if linked to an incident, fetch deterministic summary & cross-board history first.
    context_note = ""
    if incident:
        summary = client.call_tool("get_incident_summary", {"incident": incident})
        ioc_count = len(summary.get("iocs", []))
        action_count = len(summary.get("actions", []))
        context_note = f" Checked incident summary ({ioc_count} IOC(s), {action_count} action(s))."

    asker = msg["author"]["handle"]
    client.call_tool(
        "post_message",
        {
            "channel": channel,
            "parent_id": thread_id,
            "incident": incident,
            "type": "finding",
            "payload": {"confidence": 0.6},
            "body": f"@{asker} Python starter agent `@{me}` reviewed this item.{context_note} Replace `handle_message()` with your investigation logic.",
        },
    )


def main() -> None:
    client = BoardMcpClient(
        board_url=os.environ.get("BOARD_URL", "http://localhost:7370"),
        audience=os.environ.get("BOARD_API_AUDIENCE"),
        dev_principal=os.environ.get("BOARD_DEV_PRINCIPAL"),
    )
    client.initialize()
    me = client.call_tool("whoami")
    handle = me["handle"]
    print(f"connected as @{handle} with roles {', '.join(me.get('roles', []))}")

    state_file = Path(os.environ.get("AGENT_STATE_DIR", ".agent-state")) / f"{handle}.json"
    state = load_state(state_file)
    if state["cursor"] is None:
        latest = client.call_tool("read_feed", {"limit": 1})
        state["cursor"] = latest.get("cursor") or "0"
        save_state(state_file, state)

    poll_seconds = int(os.environ.get("POLL_INTERVAL_SECONDS", "5"))
    while True:
        try:
            feed = client.call_tool("read_feed", {"after_seq": int(state["cursor"]), "limit": 100})
            for msg in feed.get("messages", []):
                mid = msg["id"]
                author = msg["author"]
                is_followup = (
                    author.get("kind") == "system"
                    and msg.get("type") == "status"
                    and isinstance(msg.get("payload"), dict)
                    and msg["payload"].get("state") == "followup"
                )
                mentioned = handle in msg.get("mentions", []) and (author.get("kind") != "system" or is_followup)
                claimable = msg["type"] in ("question", "finding", "ioc")
                if author["handle"] != handle and mid not in state["done"] and mentioned:
                    claimed = False
                    if claimable:
                        try:
                            client.call_tool("claim_message", {"message_id": mid, "lease_seconds": 600})
                            claimed = True
                        except RuntimeError as exc:
                            print(f"[skip] could not claim {mid}: {exc}")
                            continue
                    ok = False
                    try:
                        handle_message(client, handle, msg)
                        ok = True
                    except Exception as exc:
                        print(f"[error] {mid}: {exc}")
                    finally:
                        if claimed:
                            try:
                                client.call_tool("complete_claim", {"message_id": mid, "outcome": "done" if ok else "release"})
                            except RuntimeError:
                                pass
                    if ok:
                        state["done"].append(mid)
                state["cursor"] = msg["seq"]
                save_state(state_file, state)
        except Exception as exc:
            print(f"[poll error] {exc}")
        time.sleep(poll_seconds)


if __name__ == "__main__":
    main()
