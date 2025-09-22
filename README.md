# Hubble Anomaly Detector

Một công cụ phát hiện bất thường mạng dựa trên dữ liệu flow từ Hubble, sử dụng rule-based detection để cảnh báo về các hoạt động đáng ngờ.

## Tính năng

- **Lắng nghe Flow Data**: Kết nối trực tiếp với Hubble server qua gRPC để nhận dữ liệu flow real-time
- **Redis-based Caching**: Sử dụng Redis để lưu trữ và xử lý flow data hiệu quả
- **Rule Engine**: Hệ thống rule engine với các quy tắc phát hiện bất thường:
  - Traffic spike detection (phát hiện tăng đột biến lưu lượng)
  - DDoS pattern detection (phát hiện mẫu DDoS)
  - High error rate detection (phát hiện tỷ lệ lỗi cao)
  - Error burst detection (phát hiện bùng nổ lỗi)
- **Real-time Alerting**: Cảnh báo ngay lập tức khi phát hiện bất thường
- **Interactive Menu**: Giao diện menu tương tác để xem flows và chạy anomaly detection
- **Detailed Statistics**: Thống kê chi tiết về Redis cache và rule engine

## Cài đặt

### Yêu cầu

- Go 1.21 hoặc cao hơn
- Redis server đang chạy (mặc định: localhost:6379)
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
  --version
```

### Các tham số

- `--hubble-server`: Địa chỉ Hubble server (mặc định: localhost:4245)
- `--version`: Hiển thị thông tin phiên bản

### Menu tương tác

Sau khi khởi động, chương trình sẽ hiển thị menu với các tùy chọn:

1. **View Flows** - Hiển thị flows real-time từ Hubble
2. **Detect Anomaly** - Chạy anomaly detection với Redis và rule engine
3. **Exit** - Thoát chương trình

## Cấu hình

### Cấu hình Redis

Redis được cấu hình mặc định với:
- **Address**: 127.0.0.1:6379
- **Password**: hoangcn8uetvnu
- **Database**: 0
- **TTL**: 5 phút cho flow data

### Cấu hình Rule Engine

Hệ thống rule engine có các rule mặc định:

1. **High Error Rate**
   - Window: 60 giây
   - Threshold: 5%
   - Severity: HIGH

2. **Traffic Spike**
   - Window: 5 phút
   - Threshold: 200% tăng so với baseline
   - Severity: HIGH

3. **Connection Flood (DDoS)**
   - Window: 10 giây
   - Threshold: 100 connections
   - Severity: CRITICAL

## Các loại Alert

### TRAFFIC_SPIKE
- **Mô tả**: Phát hiện tăng đột biến lưu lượng mạng
- **Severity**: HIGH
- **Trigger**: Khi lưu lượng tăng > 200% so với baseline

### DDOS_PATTERN
- **Mô tả**: Phát hiện mẫu tấn công DDoS
- **Severity**: HIGH
- **Trigger**: Khi có > 100 connections trong 10 giây

### HIGH_ERROR_RATE
- **Mô tả**: Tỷ lệ lỗi HTTP cao
- **Severity**: HIGH
- **Trigger**: Khi tỷ lệ lỗi > 5%

### ERROR_BURST
- **Mô tả**: Bùng nổ lỗi trong thời gian ngắn
- **Severity**: HIGH
- **Trigger**: Khi có > 10 lỗi trong 30 giây

## Cấu trúc Project

```
.
├── main.go                 # Entry point với interactive menu
├── config.go              # Configuration structures
├── hubble_grpc_client.go  # Hubble gRPC client implementation
├── anomaly_detector.go    # Anomaly detection logic với Redis
├── rule_engine.go         # Rule engine cho anomaly detection
├── flow_cache.go          # Redis-based flow caching
├── flow_types.go          # Flow data structures
├── go.mod                 # Go module file
├── go.sum                 # Go dependencies
├── Makefile               # Build và run scripts
├── docker-compose.yaml    # Docker setup
└── README.md             # Documentation
```

## Dependencies

- `github.com/cilium/cilium`: Hubble API và flow structures
- `github.com/sirupsen/logrus`: Logging
- `github.com/go-redis/redis/v8`: Redis client
- `google.golang.org/grpc`: gRPC client
- `google.golang.org/protobuf`: Protocol buffers

## Ví dụ Output

### Menu chính
```
==================================================
📋 MAIN MENU
==================================================
1. View Flows - Hiển thị flows real-time
2. Detect Anomaly - Phát hiện bất thường
3. Exit - Thoát chương trình
==================================================
Chọn option (1-3): 
```

### Anomaly Alert
```
🚨 ANOMALY DETECTED 🚨
Type: TRAFFIC_SPIKE
Severity: HIGH
Message: Traffic spike detected: Pod frontend -> api: 150000000.00 bytes (baseline: 75000000.00, increase: 200.0%)
Time: 2024-01-15 10:30:45
Stats: Flows=1250, Bytes=500000000, Errors=5, Rate=25.00/sec
--------------------------------------------------
```

### Redis Stats
```
📊 REDIS CACHE STATS
Flow Keys: 45
Window Keys: 45
Buffer Size: 12/1000
Rules: 3 enabled, 0 disabled
------------------------------
```

## Troubleshooting

### Lỗi kết nối Redis

```
Failed to connect to Redis: connection refused
```

**Giải pháp**: Đảm bảo Redis server đang chạy trên localhost:6379 với password `hoangcn8uetvnu`.

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

### Lỗi build

```
go: cannot find main module
```

**Giải pháp**: Chạy `go mod tidy` để tải dependencies và `go mod download` để tải về.

## Chạy với Docker

### Sử dụng Docker Compose

```bash
# Khởi động Redis và chạy ứng dụng
docker-compose up -d

# Xem logs
docker-compose logs -f

# Dừng services
docker-compose down
```

### Build Docker image

```bash
# Build image
docker build -t hubble-anomaly-detector .

# Chạy container
docker run -it --rm hubble-anomaly-detector
```

## Đóng góp

1. Fork repository
2. Tạo feature branch
3. Commit changes
4. Push to branch
5. Tạo Pull Request

## Changelog

### v1.1.0 - Tối ưu hóa codebase
- ✅ Loại bỏ các function không sử dụng
- ✅ Xóa `hubble_real_client.go` (không được sử dụng)
- ✅ Xóa `common.go` (chỉ chứa function không sử dụng)
- ✅ Tối ưu hóa `anomaly_detector.go` - xóa 3 functions không cần thiết
- ✅ Tối ưu hóa `rule_engine.go` - xóa 4 functions không cần thiết
- ✅ Tối ưu hóa `config.go` - xóa `DefaultConfig()` không sử dụng
- ✅ Tối ưu hóa `hubble_grpc_client.go` - xóa `GetNamespaces()` không sử dụng
- 🔄 Cập nhật README.md với thông tin mới về Redis và Rule Engine

### v1.0.0 - Phiên bản đầu tiên
- 🚀 Tính năng cơ bản: kết nối Hubble, anomaly detection
- 📊 Redis-based caching và rule engine
- 🎯 Interactive menu interface

## License

MIT License
