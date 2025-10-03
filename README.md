# Hubble Anomaly Detector

Một công cụ phát hiện bất thường mạng dựa trên dữ liệu flow từ Hubble, sử dụng rule-based detection để cảnh báo về các hoạt động đáng ngờ.

## Tính năng

- **Lắng nghe Flow Data**: Kết nối trực tiếp với Hubble server qua gRPC để nhận dữ liệu flow real-time
- **Redis-based Caching**: Sử dụng Redis để lưu trữ và xử lý flow data hiệu quả
- **Rule Engine**: Hệ thống rule engine với các quy tắc phát hiện bất thường:
  - Traffic spike detection (phát hiện tăng đột biến lưu lượng)
  - Traffic drop detection (phát hiện service chết/ngừng hoạt động)
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

Hệ thống rule engine có 4 rules mới:

1. **DDoS Spike Rule**
   - Window: 5 giây
   - Threshold: 50 flows
   - Severity: CRITICAL
   - Mục tiêu: Phát hiện DDoS attacks với >50 flows trong 5 giây

2. **Traffic Drop (Service Down)**
   - Window: 30 giây
   - Threshold: 0 flows
   - Severity: CRITICAL
   - Mục tiêu: Phát hiện service ngừng nhận request

3. **Port Scan Detection**
   - Window: 30 giây
   - Threshold: 20 unique ports
   - Severity: HIGH
   - Mục tiêu: Phát hiện 1 pod thử kết nối nhiều cổng khác nhau

4. **Cross-Namespace Traffic**
   - Window: 60 giây
   - Threshold: 1 flow
   - Severity: MEDIUM
   - Mục tiêu: Phát hiện pod gửi traffic bất thường sang namespace khác

## Cách thức hoạt động của Anomaly Detection

### 1. **Thu thập dữ liệu Flow (Data Collection)**
```
Hubble gRPC Stream → FlowCache → Redis Storage
```

**Dữ liệu được lưu trữ:**
- **Key format**: `flow:srcPod:dstPod` (ví dụ: `flow:demo-frontend-xxx:demo-api-yyy`)
- **Value format**: `port|flags|verdict` (ví dụ: `8080|443|SYN,ACK|FORWARDED`)
- **Timestamp**: Unix timestamp để sắp xếp theo thời gian
- **TTL**: 10 phút cho mỗi flow key
- **Simple Counting**: Đếm tất cả flows trong time window (không cần bucket logic)

### 2. **Phân tích theo Time Windows**
```go
// Mỗi 5 giây, hệ thống phân tích các window
func evaluateAllRules() {
    windows := flowCache.GetFlowWindows(60) // 60 giây window
    totalRequests := 0
    for _, window := range windows {
        totalRequests += window.Count
    }
    // Hiển thị: "📊 Status: X total requests in last 60s - Normal"
}
```

### 3. **Rule Processing Flow**
```
Flow Data → Time Window → Rule Evaluation → Alert Generation
```

**Ví dụ flow data:**
```
flow:demo-frontend:demo-api
├── 1705123456: 8080|443|SYN,ACK|FORWARDED
├── 1705123457: 8080|443|ACK|FORWARDED
└── 1705123458: 8080|443|FIN,ACK|FORWARDED
```

### 4. **Rule Processing Flow**
```
Time Windows → Rule Engine → 4 Detection Rules
     ↓
Metrics Calculation → Threshold Check → Alert Generation
     ↓
Status Display: "📊 Status: X requests - Normal"
Alert Display: " [time] CRITICAL DDoS Attack Detected"
```

## Các loại Alert

### DDOS_SPIKE
- **Mô tả**: Phát hiện tấn công DDoS với >50 flows trong 5 giây
- **Severity**: CRITICAL
- **Trigger**: Khi có > 50 flows trong 5 giây
- **Message**: `"DDoS Attack Detected: X flows in 5s (threshold: 50) - srcPod:dstPod"`

### TRAFFIC_DROP (Service Down)
- **Mô tả**: Phát hiện service ngừng hoạt động
- **Severity**: CRITICAL
- **Trigger**: Khi không có traffic trong 30 giây
- **Message**: `"Service Down Detected: No traffic for 30s - srcPod:dstPod"`

### PORT_SCAN
- **Mô tả**: Phát hiện port scanning với >20 unique ports
- **Severity**: HIGH
- **Trigger**: Khi có > 20 unique ports trong 30 giây
- **Message**: `"Port Scan Detected: X unique ports in 30s (threshold: 20) - srcPod:dstPod"`

### CROSS_NAMESPACE
- **Mô tả**: Phát hiện traffic bất thường sang namespace khác
- **Severity**: MEDIUM
- **Trigger**: Khi có traffic sang namespace không được phép
- **Message**: `"Cross-Namespace Traffic Detected: srcPod (srcNS) -> dstPod (dstNS) - flowKey"`

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

### Status Display (Normal)
```
📊 Status: 150 total requests in last 60s - Normal
📊 Status: 200 total requests in last 60s - Normal
```



### Status Display (Every 60 seconds)
```
📊 Status: 150 total requests in last 60s - Normal
📊 Status: 200 total requests in last 60s - Normal
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
