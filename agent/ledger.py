"""BƯỚC 3d — audit ledger append-only, tamper-evident.

Ghi nhận toàn bộ tool call vào file JSONL với chuỗi băm (hash chain) chống giả mạo.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


def append(entry: dict, path: Path) -> dict:
    """Thêm một bản ghi tool call vào ledger và tính toán hash chain."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "0" * 64
    if path.exists():
        lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                last_record = json.loads(lines[-1])
                prev_hash = last_record.get("hash", "0" * 64)
            except Exception:
                pass

    record = dict(entry)
    record["prev_hash"] = prev_hash

    # Tính sha256 từ nội dung bản ghi (bao gồm prev_hash, bỏ qua trường hash)
    record_to_hash = {k: v for k, v in record.items() if k != "hash"}
    serialized = json.dumps(record_to_hash, sort_keys=True, ensure_ascii=False)
    record["hash"] = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    line = json.dumps(record, ensure_ascii=False) + "\n"
    with path.open("a", encoding="utf-8") as f:
        f.write(line)

    return record


def verify(path: Path) -> bool:
    """Kiểm tra tính toàn vẹn của file ledger qua chuỗi băm và reason."""
    path = Path(path)
    if not path.exists():
        return False

    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return False

    expected_prev = "0" * 64
    for line in lines:
        try:
            record = json.loads(line)
        except Exception:
            return False

        # 1. Bắt buộc mọi dòng phải có reason không rỗng
        reason = record.get("reason")
        if not reason or not isinstance(reason, str) or not reason.strip():
            return False

        # 2. prev_hash phải khớp với hash của dòng trước đó
        if record.get("prev_hash") != expected_prev:
            return False

        stored_hash = record.get("hash")
        if not stored_hash:
            return False

        # 3. Tính lại hash để kiểm tra can thiệp nội dung
        record_to_hash = {k: v for k, v in record.items() if k != "hash"}
        serialized = json.dumps(record_to_hash, sort_keys=True, ensure_ascii=False)
        computed_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

        if computed_hash != stored_hash:
            return False

        expected_prev = stored_hash

    return True
