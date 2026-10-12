# Secret giả trong lịch sử Git — Điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks phiên bản v8.30.1.
- Commit chứa token giả: Commit 1bdd849.
- File, rule và kết quả quét lịch sử:
  + Lệnh thực hiện: gitleaks git --config .gitleaks.toml --redact .
  + Rule kích hoạt: lab24-synthetic-token (từ cấu hình .gitleaks.toml).
  + Kết quả: Phát hiện 1 finding tại commit 1bdd849 trong file token giả cài sẵn; tiến trình trả về exit code 1 (đây là kết quả mong đợi của bài tập để chứng minh khả năng rà soát lịch sử Git).
- Kết quả quét file hiện tại:
  + Lệnh thực hiện: gitleaks dir --config .gitleaks.toml --redact .
  + Kết quả: Hoàn toàn sạch, trả về exit code 0; không có secret nào tồn tại trong thư mục làm việc ở nhánh hiện tại (HEAD).
- Nếu đây là credential thật, cần xử lý thế nào:
  + Lập tức thu hồi (revoke) và đảo quyền / rotate token trực tiếp tại nhà cung cấp dịch vụ hoặc hệ thống phát hành token.
  + Kiểm tra nhật ký truy cập (access log) và audit log của dịch vụ tương ứng để rà soát các hành vi bất thường hoặc truy cập trái phép trong khoảng thời gian token bị lộ.
  + Xóa sạch các bản sao lưu, fork hoặc cache có chứa token bị lộ sau khi đã hoàn tất rotate.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  + Xóa file ở commit mới chỉ làm file không còn xuất hiện trong cây thư mục của commit hiện tại, nhưng toàn bộ lịch sử commit cũ trong cơ sở dữ liệu đối tượng của Git vẫn lưu trữ nguyên vẹn bản ghi và giá trị của token. Bất kỳ ai clone repo đều có thể xem lại lịch sử qua git log hoặc git checkout 1bdd849 để lấy lại token.
  + Pin dependency trong requirements.lock và pre-commit hook chỉ có tác dụng ngăn ngừa tấn công chuỗi cung ứng mã nguồn và ngăn chặn vô tình commit secret mới trong tương lai; chúng hoàn toàn không có khả năng vô hiệu hóa quyền hạn của một credential đã bị lộ nếu chưa được thu hồi và rotate trên máy chủ quản trị.
