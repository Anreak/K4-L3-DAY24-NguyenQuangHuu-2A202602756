# DPIA-lite — Điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- Dữ liệu ticket khiếu nại (phân loại internal, đầu vào untrusted): Nội dung phản hồi trong thư mục corpus/*.md do người dùng hoặc bên ngoài cung cấp, có thể chứa chỉ thị tấn công prompt injection gián tiếp.
- Dữ liệu thông tin cá nhân khách hàng (phân loại restricted, PII nhạy cảm): Chứa các trường nhạy cảm gồm mã khách hàng KH-xxxxxx, họ tên, CCCD 12 số, số điện thoại, tài khoản ngân hàng STK và email trong data/customers.json.
Note: Toàn bộ dữ liệu khách hàng và PII trong bài lab là dữ liệu giả lập (synthetic data), tuyệt đối không chứa thông tin của người thật.

2. Mục đích xử lý và principal:
- support_l1 (Nhân viên hỗ trợ cấp 1): Mục đích tóm tắt nội dung yêu cầu (summarize-tickets) và xử lý yêu cầu cơ bản (support-reply). Quyền hạn chỉ cho phép gọi search_docs, bị từ chối truy cập kho dữ liệu cá nhân read_customer.
- dpo (Nhân viên bảo vệ dữ liệu cá nhân): Mục đích giải quyết phản hồi (support-reply) và kiểm toán dữ liệu (privacy-audit). Được phép gọi read_customer đối với khách hàng có liên kết hợp lệ với ticket, nhưng tuyệt đối không được phép gửi dữ liệu ra bên ngoài.
- billing (Kế toán thanh toán): Mục đích đối soát thanh toán (billing-reconciliation) và tóm tắt ticket.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A: Tiếp nhận câu hỏi người dùng, gọi tool search_docs đọc corpus ticket. Toàn bộ nội dung văn bản tự do được che giấu PII qua pii.redact(). Chỉ các mã số ticket dạng số trích xuất từ tên tệp (ví dụ ticket-901.md -> 901) được đưa qua ranh giới sang Run B.
- Run B: Tiếp nhận danh sách ticket_id, đối chiếu trường related_tickets trong nguồn tin cậy data/customers.json để xác định khách hàng thực sự liên quan. Gọi read_customer sau khi qua cổng kiểm tra chính sách.
- Cổng kiểm soát Policy PEP: Đặt ngay trước mọi lời gọi tool (search_docs, read_customer, http_post) để kiểm tra thẩm quyền, mục đích và thời hạn hiệu lực.
- Endpoint đích: Sink kiểm thử cục bộ tại http://127.0.0.1:10024/reconcile. Mọi lệnh gửi dữ liệu restricted ra endpoint này đều bị chính sách từ chối.
- Audit Ledger: Tệp reports/ledger.jsonl lưu lại mọi quyết định allow/deny kèm mã băm tham số (args_hash) và chuỗi băm tamper-evident.

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng kiểm thử:
  + Quyền tối thiểu OBO: support_l1 bị từ chối gọi read_customer (dòng decision=deny trong ledger); dpo được phép gọi read_customer cho khách hàng gắn với ticket hợp lệ (dòng decision=allow).
  + Ngăn chặn rò rỉ: Lệnh gửi dữ liệu ra sink bị chặn đứng (decision=deny cho http_post); tệp reports/attack-after.log rỗng hoàn toàn (0 byte).
  + Chống thao túng gián tiếp: Khách hàng KH-000777 chỉ được nhắc trong free text của kẻ tấn công không bao giờ bị đọc vì không có ticket liên kết trong data/customers.json.
- Giới hạn kỹ thuật của bài lab:
  + Mock LLM: Hoạt động theo quy tắc khớp mẫu giả lập để bảo đảm tính tất định và độ tái lập của bài lab, không đại diện cho toàn bộ hành vi phức tạp của các mô hình LLM lớn ngoài đời thực.
  + Quyền giả lập (--as): Đọc trực tiếp vai trò từ file JSON cấu hình, không thay thế cho hệ thống xác thực tập trung production (OAuth2/OIDC/IAM).
  + PII Gate bằng Regex: Nhận diện theo mẫu số cố định, có thể bỏ sót các định dạng phi chuẩn hoặc phương ngữ địa phương nếu không có mô hình học sâu NER.
  + Hash chain đơn tệp: Phát hiện sửa đổi nội dung giữa file nhưng không ngăn được việc xóa dòng cuối nếu không có cơ chế đối chiếu mốc tin cậy bên ngoài.
