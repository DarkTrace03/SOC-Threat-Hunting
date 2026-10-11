# SOC Threat Hunting

Threat Hunting trên Splunk, tập trung vào các truy vấn SPL cho môi trường Windows và Linux, yêu cầu telemetry, hướng điều tra và ánh xạ MITRE ATT&CK khi có căn cứ.


## Cấu trúc repository

```text
SOC-Threat-Hunting/
├── README.md
├── checklists/
│   └── SOC_Threat_Hunting_Checklist_SPL_Final.md
└── spl/
    └── README.md
```

## Bắt đầu

1. Mở [checklists/SOC_Threat_Hunting_Checklist_SPL_Final.md](checklists/SOC_Threat_Hunting_Checklist_SPL_Final.md).
2. Chọn hunt phù hợp với hệ thống và nguồn log hiện có.
3. Kiểm tra index, sourcetype, field, data model, macro và quyền truy cập mà truy vấn yêu cầu.
4. Chạy thử trên dữ liệu được phép sử dụng; xác nhận kết quả trước khi xem truy vấn là đã kiểm thử.
5. Ghi lại kết quả, giới hạn, false positive và các bước điều tra tiếp theo.


## Phạm vi và tuyên bố

Repository này phục vụ học tập, nghiên cứu và hỗ trợ quy trình phân tích an ninh. Nội dung không thay thế quy trình ứng phó sự cố, đánh giá của chuyên gia hoặc kiểm thử trong môi trường đích.
