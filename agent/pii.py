"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store.

Nhận diện và che giấu các giá trị nhạy cảm (PII) trong văn bản tiếng Việt.
Hỗ trợ 4 loại thực thể:
- VN_CCCD: Căn cước công dân 12 chữ số.
- VN_PHONE: Số điện thoại 10 chữ số bắt đầu bằng 0.
- VN_BANK_ACCOUNT: Số tài khoản ngân hàng từ 8-16 chữ số, thường đi kèm nhãn STK.
- EMAIL: Địa chỉ thư điện tử.
"""
from __future__ import annotations

import re

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
BANK_KEYWORD_PATTERN = re.compile(r"(?i:\b(?:stk|số tài khoản|tài khoản|tk)\s*[:.]?\s*)(\d{8,16})\b")
BANK_LONG_PATTERN = re.compile(r"\b\d{13,16}\b")
CCCD_PATTERN = re.compile(r"\b\d{12}\b")
PHONE_PATTERN = re.compile(r"\b0\d{9}\b")


def _is_overlapping(start: int, end: int, entities: list[dict]) -> bool:
    return any(start < e["end"] and end > e["start"] for e in entities)


def detect(text: str) -> list[dict]:
    """Phát hiện các thực thể PII trong chuỗi text.

    Trả về danh sách dict: [{"type": str, "start": int, "end": int}]
    """
    if not text:
        return []

    entities: list[dict] = []

    # 1. Phát hiện EMAIL
    for match in EMAIL_PATTERN.finditer(text):
        entities.append({"type": "EMAIL", "start": match.start(), "end": match.end()})

    # 2. Phát hiện VN_BANK_ACCOUNT (ưu tiên các cụm có từ khóa STK / tài khoản)
    for match in BANK_KEYWORD_PATTERN.finditer(text):
        start = match.start(1)
        end = match.end(1)
        if not _is_overlapping(start, end, entities):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    # Các chuỗi số tài khoản dài từ 13 đến 16 số không trùng với thực thể trước đó
    for match in BANK_LONG_PATTERN.finditer(text):
        start = match.start()
        end = match.end()
        if not _is_overlapping(start, end, entities):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": start, "end": end})

    # 3. Phát hiện VN_CCCD (chính xác 12 chữ số)
    for match in CCCD_PATTERN.finditer(text):
        start = match.start()
        end = match.end()
        if not _is_overlapping(start, end, entities):
            entities.append({"type": "VN_CCCD", "start": start, "end": end})

    # 4. Phát hiện VN_PHONE (10 chữ số bắt đầu bằng 0)
    for match in PHONE_PATTERN.finditer(text):
        start = match.start()
        end = match.end()
        if not _is_overlapping(start, end, entities):
            entities.append({"type": "VN_PHONE", "start": start, "end": end})

    # Sắp xếp các thực thể theo thứ tự vị trí xuất hiện trong chuỗi
    entities.sort(key=lambda item: item["start"])
    return entities


def redact(text: str) -> str:
    """Che các thực thể PII bằng nhãn [REDACTED_<TYPE>].

    Thay thế từ cuối chuỗi về đầu để không làm sai lệch vị trí các ký tự chưa xử lý.
    """
    if not text:
        return text

    entities = detect(text)
    # Sắp xếp từ cuối về đầu theo offset
    for entity in sorted(entities, key=lambda item: item["start"], reverse=True):
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[: entity["start"]] + replacement + text[entity["end"] :]

    return text
