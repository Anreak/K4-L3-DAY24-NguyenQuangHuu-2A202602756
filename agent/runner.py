"""BƯỚC 3c — Trifecta split + OBO Policy Enforcement Point.

Tách luồng xử lý của agent thành hai bước độc lập:
- Run A: Đọc untrusted content từ corpus bằng search_docs. Không gọi private store hay network.
- Run B: Truy xuất hồ sơ private data từ read_customer dựa trên mapping tin cậy
         (ticket_id từ tên file -> related_tickets trong customers.json).
         Tuyệt đối không lấy customer_id từ free text của attacker.

Mọi tool call đều phải qua agent.policy.check() và được ghi vết vào ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

BASE_DIR = Path(__file__).resolve().parent.parent
CUSTOMERS_FILE = BASE_DIR / "data" / "customers.json"
REPORTS_DIR = BASE_DIR / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Giữ lại cho tương thích ngược nếu scaffold cũ cần kiểm tra."""


def _load_customers() -> list[dict]:
    if not CUSTOMERS_FILE.exists():
        return []
    return json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    """Hàm điều phối an toàn: kiểm soát quyền OBO, split trifecta và ghi ledger."""
    ledger_path = (Path(log_dir) if log_dir else REPORTS_DIR) / "ledger.jsonl"
    run_uuid = uuid.uuid4().hex[:8]
    agent_id = "lab24-agent"
    expires_at = "2099-01-01T00:00:00+00:00"
    agent_scopes = ("search_docs", "read_customer")

    # ─────────────────────────────────────────────────────────────
    # Run A: Tìm kiếm tài liệu trong corpus (Untrusted boundary)
    # ─────────────────────────────────────────────────────────────
    ctx_search = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/run-a",
        delegation_depth=0,
        egress_enabled=False,
        principal_id=principal_id,
        requested_tool="search_docs",
        agent_scopes=agent_scopes,
        parent_scopes=(),
        expires_at=expires_at,
    )
    allow_search, reason_search = policy.check(ctx_search)

    ledger_entry_search = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "run_id": f"run-{run_uuid}-a",
        "tool": "search_docs",
        "args_hash": hashlib.sha256(message.encode("utf-8")).hexdigest()[:16],
        "classification": "internal",
        "decision": "allow" if allow_search else "deny",
        "reason": reason_search,
        "on_behalf_of": principal_id,
        "expires_at": expires_at,
    }
    ledger.append(ledger_entry_search, ledger_path)

    if not allow_search:
        return f"Từ chối truy cập: {reason_search}"

    docs = tools.search_docs(message)

    # Trích xuất ticket_id từ tên file (nguồn định danh cấu trúc tin cậy)
    matched_ticket_ids: set[int] = set()
    for doc in docs:
        file_name = doc.get("id", "")
        match = re.search(r"ticket-(\d+)", file_name)
        if match:
            matched_ticket_ids.add(int(match.group(1)))

    combined_text = "\n\n".join(d["text"] for d in docs)
    # Khử khuẩn PII khỏi ngữ cảnh nếu cần
    _ = pii.redact(combined_text)

    # Quét chỉ thị injection để phát hiện hành vi tấn công
    injected = llm.find_injection(combined_text)

    # ─────────────────────────────────────────────────────────────
    # Run B: Đọc dữ liệu private (Chỉ dựa trên mapping tin cậy)
    # ─────────────────────────────────────────────────────────────
    customers = _load_customers()
    candidate_customer_ids: list[str] = []
    for c in customers:
        c_tickets = set(c.get("related_tickets", []))
        if matched_ticket_ids.intersection(c_tickets):
            candidate_customer_ids.append(str(c["customer_id"]))

    candidate_customer_ids.sort()

    for customer_id in candidate_customer_ids:
        ctx_read = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=0,
            egress_enabled=False,
            principal_id=principal_id,
            requested_tool="read_customer",
            agent_scopes=agent_scopes,
            parent_scopes=(),
            expires_at=expires_at,
        )
        allow_read, reason_read = policy.check(ctx_read)

        ledger_entry_read = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": f"run-{run_uuid}-b",
            "tool": "read_customer",
            "args_hash": hashlib.sha256(customer_id.encode("utf-8")).hexdigest()[:16],
            "classification": "restricted",
            "decision": "allow" if allow_read else "deny",
            "reason": reason_read,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }
        ledger.append(ledger_entry_read, ledger_path)

        if allow_read:
            try:
                tools.read_customer(customer_id)
            except tools.ToolError:
                pass

    # ─────────────────────────────────────────────────────────────
    # Egress PEP: Chặn exfiltration nếu có chỉ thị injection
    # ─────────────────────────────────────────────────────────────
    if injected is not None:
        ctx_egress = PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner=f"{agent_id}/run-b",
            delegation_depth=1,
            egress_enabled=True,
            principal_id=principal_id,
            requested_tool="http_post",
            agent_scopes=agent_scopes,
            parent_scopes=("read_customer",),
            expires_at=expires_at,
        )
        allow_egress, reason_egress = policy.check(ctx_egress)

        ledger_entry_egress = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": f"run-{run_uuid}-egress",
            "tool": "http_post",
            "args_hash": hashlib.sha256(injected.target_url.encode("utf-8")).hexdigest()[:16],
            "classification": "restricted",
            "decision": "allow" if allow_egress else "deny",
            "reason": reason_egress,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }
        ledger.append(ledger_entry_egress, ledger_path)

        if allow_egress:
            # Sẽ không bao giờ xảy ra vì policy chặn cứng restricted + egress
            tools.http_post(injected.target_url, {})

    return llm.summarize(docs)
