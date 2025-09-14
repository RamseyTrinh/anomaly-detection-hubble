# Hubble Anomaly Detector

Một công cụ phát hiện bất thường mạng dựa trên dữ liệu flow từ Hubble, sử dụng rule-based detection để cảnh báo về các hoạt động đáng ngờ.

## Tính năng

- **Lắng nghe Flow Data**: Kết nối trực tiếp với Hubble server để nhận dữ liệu flow real-time
- **Rule-based Anomaly Detection**: Phát hiện các bất thường dựa trên các quy tắc có thể cấu hình:
  - High bandwidth usage (sử dụng băng thông cao)
  - Unusual port activity (hoạt động port bất thường)
  - Unusual destination connections (kết nối đến địa chỉ bất thường)
  - High packet drop rate (tỷ lệ drop packet cao)
  - High connection rate (tỷ lệ kết nối cao)
- **Real-time Alerting**: Cảnh báo ngay lập tức khi phát hiện bất thường
- **Detailed Logging**: Ghi log chi tiết và lưu trữ alerts
- **Configurable Thresholds**: Có thể cấu hình các ngưỡng cảnh báo

## Cài đặt

### Yêu cầu

- Go 1.21 hoặc cao hơn
- Hubble server đang chạy và có thể truy cập
- Cilium đã được cài đặt và cấu hình

### Build

```bash
go mod tidy
go build -o hubble-anomaly-detector
```

## Sử dụng

### Chạy cơ bản

```bash
./hubble-anomaly-detector
```

### Với các tùy chọn

```bash
./hubble-anomaly-detector \
  --hubble-server=localhost:4245 \
  --alert-log=alerts.log \
  --log-level=info
```

### Các tham số

- `--hubble-server`: Địa chỉ Hubble server (mặc định: localhost:4245)
- `--alert-log`: File log cho alerts (mặc định: alerts.log)
- `--log-level`: Mức độ log (debug, info, warn, error)
- `--config`: File cấu hình JSON (tùy chọn)
- `--version`: Hiển thị thông tin phiên bản

## Cấu hình

### Cấu hình mặc định

```json
{
  "hubble_server": "localhost:4245",
  "flow_filters": [],
  "check_interval": "5s",
  "alert_thresholds": {
    "high_bandwidth_threshold": 100000000,
    "high_connection_threshold": 1000,
    "unusual_port_threshold": 50,
    "drop_rate_threshold": 5.0,
    "time_window": "60s",
    "unusual_destination_threshold": 100
  },
  "log_level": "info"
}
```

### Giải thích các ngưỡng

- **high_bandwidth_threshold**: Ngưỡng băng thông cao (bytes/s)
- **high_connection_threshold**: Ngưỡng kết nối cao (connections/s)
- **unusual_port_threshold**: Ngưỡng port bất thường (số kết nối)
- **drop_rate_threshold**: Ngưỡng tỷ lệ drop packet (%)
- **time_window**: Cửa sổ thời gian phân tích
- **unusual_destination_threshold**: Ngưỡng địa chỉ đích bất thường

## Các loại Alert

### HIGH_BANDWIDTH
- **Mô tả**: Phát hiện sử dụng băng thông cao bất thường
- **Severity**: HIGH
- **Trigger**: Khi byte rate vượt quá ngưỡng

### UNUSUAL_PORT
- **Mô tả**: Hoạt động kết nối đến các port không phổ biến
- **Severity**: MEDIUM
- **Trigger**: Khi số kết nối đến port lạ vượt quá ngưỡng

### UNUSUAL_DESTINATION
- **Mô tả**: Kết nối đến các địa chỉ đích bất thường
- **Severity**: HIGH
- **Trigger**: Khi số kết nối đến địa chỉ lạ vượt quá ngưỡng

### HIGH_DROP_RATE
- **Mô tả**: Tỷ lệ drop packet cao
- **Severity**: HIGH
- **Trigger**: Khi tỷ lệ drop vượt quá ngưỡng

### HIGH_CONNECTION_RATE
- **Mô tả**: Tỷ lệ kết nối cao bất thường
- **Severity**: MEDIUM
- **Trigger**: Khi connection rate vượt quá ngưỡng

## Cấu trúc Project

```
.
├── main.go                 # Entry point
├── config.go              # Configuration structures
├── hubble_grpc_client.go  # Hubble gRPC client implementation
├── hubble_real_client.go  # Hubble real client implementation
├── anomaly_detector.go    # Anomaly detection logic
├── alert_handler.go       # Alert handling and output
├── flow_types.go          # Flow data structures
├── go.mod                 # Go module file
└── README.md             # Documentation
```

## Dependencies

- `github.com/cilium/cilium`: Hubble API và flow structures
- `github.com/sirupsen/logrus`: Logging
- `google.golang.org/grpc`: gRPC client
- `google.golang.org/protobuf`: Protocol buffers

## Ví dụ Output

```
[2024-01-15 10:30:45] HIGH: HIGH_BANDWIDTH: High bandwidth detected: 150000000.00 bytes/s (threshold: 100000000)
  Flow Details:
    Time: 2024-01-15T10:30:45Z
    Verdict: FORWARDED
    Source IP: 192.168.1.100
    Destination IP: 10.0.0.50
    Protocol: TCP
    Source Port: 12345
    Destination Port: 80
    Flags: SYN,ACK
  Current Statistics:
    Total Flows: 1250
    Total Bytes: 500000000
    Total Connections: 150
    Flow Rate: 25.00 flows/s
    Byte Rate: 150000000.00 bytes/s
    Connection Rate: 3.00 connections/s
    Drop Rate: 0.50%
---
```

## Troubleshooting

### Lỗi kết nối Hubble

```
Failed to connect to Hubble server: connection refused
```

**Giải pháp**: Đảm bảo Hubble server đang chạy và có thể truy cập từ địa chỉ được cấu hình.

### Lỗi gRPC

```
Failed to start flow streaming: rpc error: code = Unavailable
```

**Giải pháp**: Kiểm tra kết nối mạng và cấu hình Hubble server.

## Đóng góp

1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Push to branch
5. Tạo Pull Request

## License

MIT License
