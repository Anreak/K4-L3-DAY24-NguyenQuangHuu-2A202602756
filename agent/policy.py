"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call.

Cổng kiểm soát chính sách trước khi bất kỳ công cụ nào được thực thi.
Đảm bảo mọi quyết định (allow hay deny) đều đi kèm lý do giải thích (reason).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PRINCIPALS_FILE = BASE_DIR / "data" / "principals.json"

VALID_CLASSIFICATIONS = {"public", "internal", "restricted"}


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def _load_principals() -> dict[str, dict]:
    if not PRINCIPALS_FILE.exists():
        return {}
    return json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))


def check(context: PolicyContext) -> tuple[bool, str]:
    """Kiểm tra điều kiện chính sách đối với một lần gọi công cụ.

    Trả về (allow, reason). Biến reason không bao giờ được để trống.
    """
    # 1. Kiểm tra phân loại dữ liệu hợp lệ
    if context.data_classification not in VALID_CLASSIFICATIONS:
        return False, f"Phân loại dữ liệu không hợp lệ: {context.data_classification}"

    # 2. Rule tối thiểu: dữ liệu restricted đi kèm kết nối mạng (egress) phải bị từ chối
    if context.data_classification == "restricted" and context.egress_enabled is True:
        return False, "Dữ liệu restricted không được phép gọi network/egress"

    # 3. Kiểm tra danh tính người ra lệnh (principal)
    principals = _load_principals()
    if not context.principal_id or context.principal_id not in principals:
        return False, f"Principal không tồn tại hoặc chưa được xác thực: {context.principal_id}"

    principal_info = principals[context.principal_id]

    # 4. Kiểm tra thời hạn hiệu lực của phiên làm việc (expires_at)
    if context.expires_at:
        try:
            exp_dt = datetime.fromisoformat(context.expires_at)
            # Chuẩn hóa về UTC nếu chưa có timezone
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            now_dt = datetime.now(timezone.utc)
            if exp_dt < now_dt:
                return False, f"Phiên làm việc đã hết hạn tại thời điểm: {context.expires_at}"
        except ValueError:
            return False, f"Định dạng expires_at không hợp lệ: {context.expires_at}"

    # 5. Kiểm tra quyền của công cụ được yêu cầu (requested_tool)
    if context.requested_tool:
        allowed_tools = principal_info.get("allowed_tools", [])
        if context.requested_tool not in allowed_tools:
            return (
                False,
                f"Công cụ {context.requested_tool} không nằm trong danh sách được phép của {context.principal_id}",
            )

        if context.agent_scopes and context.requested_tool not in context.agent_scopes:
            return False, f"Công cụ {context.requested_tool} vượt quá phạm vi agent_scopes"

        # Nếu là ủy quyền qua nhiều tầng (delegation_depth > 0), quyền không được mở rộng hơn cha
        if context.delegation_depth > 0:
            if context.requested_tool not in context.parent_scopes:
                return (
                    False,
                    f"Công cụ {context.requested_tool} vượt quá parent_scopes khi delegation_depth={context.delegation_depth}",
                )

    # 6. Kiểm tra mục đích sử dụng (request_purpose)
    if context.request_purpose:
        allowed_purposes = principal_info.get("purposes", [])
        if context.request_purpose not in allowed_purposes:
            return (
                False,
                f"Mục đích {context.request_purpose} không nằm trong danh sách cho phép của {context.principal_id}",
            )

    # Mọi điều kiện kiểm tra đều hợp lệ
    return True, f"Cho phép: {context.principal_id} được gọi {context.requested_tool} cho mục đích {context.request_purpose}"
