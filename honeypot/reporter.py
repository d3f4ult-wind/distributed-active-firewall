# reporter.py — Báo cáo IP xấu lên kênh đồng bộ trung tâm
#
# Chức năng: Publish IP kẻ tấn công lên Redis channel theo định dạng channel_schema.md.
# Đây là bước 'Phát tín hiệu' trong chu trình Phát hiện -> Đồng bộ -> Chặn.
# Tất cả Edge Node đang subscribe sẽ nhận được thông tin này gần như tức thời.