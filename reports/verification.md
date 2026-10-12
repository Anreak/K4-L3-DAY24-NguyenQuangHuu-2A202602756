# Verification — Điền trước khi nộp

- OS / Python / Gitleaks version: Windows / Python 3.12 / Gitleaks v8.30.1
- python -m pytest tests/ -q: Toàn bộ test pass (18 passed, 0 skipped, 0 failed)
- pre-commit run --all-files: Passed (gitleaks-system hook pass trên toàn bộ tệp)
- Ledger verify: True (mọi dòng có reason, hash chain SHA-256 toàn vẹn)
- Kích thước attack-after.log: 0 byte (không có dữ liệu rò rỉ ra sink)
- Các lỗi còn lại: Không còn lỗi tồn đọng

---

## 1. Checkpoint 1 & 2: Baseline và Red team
- Lệnh kiểm tra lure: python -m agent.check_lure corpus/ticket-90*.md
- Kết quả: 4/4 lure sẵn sàng (ticket-901 HTML comment, ticket-902 CSS styling ẩn, ticket-903 giả mạo thẩm quyền admin/DPO, cặp ticket-904 và ticket-904b phân mảnh payload).
- Bằng chứng rò rỉ ban đầu: reports/attack-before.log ghi nhận 4 bản ghi POST thành công dữ liệu synthetic của KH-000999 tới sink.

## 2. Checkpoint 3a: PII Gate
- Lệnh kiểm tra: python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp
- Kết quả trên tập tests/vn_pii_testset.jsonl:
  + gold: 110
  + pred: 110
  + true positive (tp): 110
  + precision: 1.000 (100%)
  + recall: 1.000 (100%)
- Giới hạn: Nhận diện theo mẫu regex cố định, chưa bao quát các phương ngữ hoặc cấu trúc số phi tiêu chuẩn nếu không có mô hình học sâu NER.

## 3. Checkpoint 3b & 3c: Policy PEP và OBO
- Lệnh kiểm tra:
  + python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp
  + python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp
- Kết quả: PASS toàn bộ. Rule tối thiểu chặn đứng restricted + egress; support_l1 bị từ chối truy cập kho dữ liệu cá nhân, trong khi dpo được phép đọc khách hàng hợp lệ theo đúng mục đích; ledger ghi nhận đầy đủ on_behalf_of, run_id, expires_at và reason.

## 4. Checkpoint 3d & 3e: Trifecta Split và Ledger
- Lệnh kiểm tra:
  + python -m pytest tests/test_split.py -v --basetemp=.pytest_tmp
  + python -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp
  + python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp
- Kết quả: PASS toàn bộ. Run B chỉ nhận ticket_id số từ tên file, khách hàng KH-000777 trong free text không bao giờ bị đọc; test_injection.py chạy đủ 4 biến thể × 2 principal không bị skip; chuỗi băm của ledger phát hiện can thiệp sửa đổi trái phép.

## 5. Checkpoint 4 & 5: Supply chain và Prove
- Lệnh kiểm tra:
  + python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp
  + gitleaks git --config .gitleaks.toml --redact . (exit code 1, bắt đúng token giả ở commit 1bdd849)
  + gitleaks dir --config .gitleaks.toml --redact . (exit code 0, thư mục làm việc hiện tại sạch)
- Kết quả chứng minh: attack-after.log đạt 0 byte khi chạy với vai trò dpo; ledger ghi nhận dòng chặn http_post với decision=deny và reason giải thích rõ ràng.
