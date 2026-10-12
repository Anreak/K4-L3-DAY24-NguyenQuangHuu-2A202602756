# Baseline — Điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa. Hàm _naive_loop(message, llm) tại agent/loop.py:27 nhận chuỗi câu hỏi message và đối tượng llm, không có tham số hay cơ chế thiết lập agent_id, run_id hoặc danh tính người dùng để kiểm tra quyền hạn. 

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có phần nào kiểm tra mục đích, quyền hạn hay phân loại dữ liệu trước khi gọi http_post. Bên gửi: llm.find_injection() trích xuất tại agent/loop.py:34-35. _naive_loop gọi trực tiếp tools.http_post() tại agent/loop.py:44 mà không kiểm duyệt, agent/tools.py:76-83 chỉ kiểm tra cứng máy chủ đích thuộc 127.0.0.1:10024, tránh gửi ra ngoài Internet.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Body POST: agent/loop.py:44 với cấu trúc {"records": collected}. Bằng chứng sink đã nhận body: reports/sink.log bằng handler do make_handler() tạo ra tại sink/sink.py:45-47, rồi được sao chép thành reports/attack-before.log.
