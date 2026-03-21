# Distributed Active Firewall
    Hiện nay, việc đặt một tường lửa duy nhất ở cổng mạng (Gateway) thường tạo ra nút thắt 
cổ chai về tốc độ, hiệu năng và rủi ro sập toàn hệ thống nếu thiết bị này gặp sự cố. Hơn 
nữa, tường lửa truyền thống thường chỉ chặn thụ động, khó giúp quản trị viên nắm bắt 
được hành vi của kẻ tấn công. 
    Vì vậy, mục tiêu cốt lõi của đồ án là tập trung giải quyết bài toán phân tán sự kiểm soát 
mạng. Cụ thể: 
    1. Chuyển quyền chặn lọc về các nút biên: Thay vì dồn về trung tâm, hệ thống sẽ 
đặt các nút kiểm duyệt nhỏ gọn tại từng phân vùng mạng để san sẻ tải. Đồ án dự 
kiến dùng XDP/eBPF để minh họa cho khả năng can thiệp gói tin ở tốc độ cao, tốn 
ít tài nguyên, đồng thời kết hợp với tường lửa truyền thống để tạo thành một hệ 
thống đa trạng thái (multistate) 
    2. Tự động hóa phòng thủ (Phòng thủ chủ động): Kết hợp một mạng bẫy 
(Honeypot) để dụ kẻ tấn công. Khi có kẻ sập bẫy, hệ thống sẽ tự động đồng bộ 
danh sách đen (Blacklist) để tất cả các nút mạng phân tán cùng chặn IP đó ngay 
lập tức. 
    (Điểm nhấn của đồ án: Không hướng tới các giải pháp cồng kềnh của doanh nghiệp lớn, 
đồ án tập trung xây dựng một quy trình khép kín, tinh gọn, ứng dụng được ngay cho các 
mạng cục bộ/mạng biên quy mô nhỏ theo cơ chế “Phát hiện → Đồng bộ → Chặn”). 
# Cập nhật file này mỗi khi có thay đổi lớn về cấu trúc hoặc cách chạy hệ thống.