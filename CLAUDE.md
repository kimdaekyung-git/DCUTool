# DCUTool 프로젝트 - Claude AI 컨텍스트 문서

> 이 문서는 Claude AI가 DCUTool 프로젝트를 이해하고 효과적으로 작업하기 위한 컨텍스트 정보를 제공합니다.

## 프로젝트 개요

**DCUTool**은 원격 검침 시스템을 위한 GUI 애플리케이션입니다. FEP(Frontend Processor)가 DCU(Data Collection Unit)를 통해 RCU(Remote Collection Unit) 및 TCU(Terminal Collection Unit)의 계량기 데이터를 수집하고 관리하는 시스템입니다.

### 핵심 개념

1. **FEP** (Frontend Processor)
   - 서버 역할, DCU로부터 연결을 수락
   - 포트 9008에서 대기
   - 여러 DCU 연결 관리

2. **DCU** (Data Collection Unit)
   - 데이터 수집 장치
   - FEP에 연결하여 데이터 전송
   - RCU와 통신하여 TCU 데이터 수집

3. **RCU** (Remote Collection Unit)
   - 원격 수집 장치
   - 여러 TCU 관리
   - RCU ID: 0-255

4. **TCU** (Terminal Collection Unit)
   - 말단 수집 장치
   - 실제 계량기와 연결
   - TCU ID: 0-255

5. **RMU** (Remote Metering Unit)
   - RCU + TCU의 조합
   - RMU ID = [RCU ID, TCU ID] (2 bytes)

## 아키텍처

### 디렉토리 구조

```
DCUTool/
├── src/
│   ├── app.py                    # [중요] GUI 메인 애플리케이션
│   ├── service_mode.py           # 서비스 모드 (자동 재연결)
│   ├── system_arch.py            # 모듈형 아키텍처 (API 서버)
│   └── dcutools/
│       ├── __init__.py           # 모듈 exports
│       ├── protocol.py           # [핵심] 프로토콜 구현
│       ├── client.py             # TCP 클라이언트
│       ├── server.py             # TCP 서버
│       └── transport.py          # 공통 인터페이스
├── FepServer_init.ini            # 설정 파일
├── Login.txt                     # 로그인 이력
├── YYYYMMDD_data.txt            # 일일 데이터 로그
├── plan.md                       # 개발 계획
└── CLAUDE.md                    # 이 파일
```

### 주요 모듈 설명

#### 1. `protocol.py` - 프로토콜 레이어 (696 lines)

**가장 중요한 파일입니다. 모든 통신 프로토콜이 여기에 정의되어 있습니다.**

주요 클래스 및 함수:
- `Command(enum.IntEnum)`: 명령어 코드 정의
  - 요청: `DCU_INFO_REQUEST`, `RMU_INFO_REQUEST`, `CURRENT_READING_REQUEST` 등
  - 응답: `DCU_INFO_RESPONSE`, `RMU_INFO_RESPONSE`, `CURRENT_READING_RESPONSE` 등

- `Frame(dataclass)`: 디코딩된 프레임 구조
  ```python
  @dataclass
  class Frame:
      ver: int          # Version
      did: int          # Destination ID
      sid: int          # Source ID
      length: int       # Payload length
      cmd: int          # Command code
      data: bytes       # Payload data
      checksum: int     # Checksum
      raw: bytes        # Raw frame
  ```

- `FrameEncoder`: 프레임 생성 및 인코딩
  - DLE escaping 적용
  - Checksum 계산
  - SOF/EOF 추가

- `FrameDecoder`: 스트리밍 디코더
  - SOF/EOF 감지
  - DLE unescaping
  - 프레임 분리

- `PacketParser`: 프레임 페이로드 파싱
  - DCU 정보 파싱
  - RMU 정보 파싱
  - 계량 데이터 파싱 (M-BUS 프로토콜)

**핵심 프레임 구조:**
```
[SOF:0xE1] [VER] [DID:2] [SID:2] [LEN] [CMD] [DATA...] [CHK] [EOF:0xE2]
```

**DLE Escaping 규칙:**
- 데이터에 `0xE1`, `0xE2`, `0x10`이 포함되면:
  - `0x10` (DLE) 삽입 후 `원래값 + 0x10` 전송
  - 예: `0xE1` → `0x10 0xF1`

#### 2. `app.py` - GUI 애플리케이션 (1,281 lines)

Tkinter 기반 GUI, 주요 기능:
- DCU 연결 관리
- RMU 정보 조회
- 실시간 검침 데이터 표시
- DCU/RMU 설정
- 터미널 모드 (커스텀 명령 전송)
- 자동 ACK 응답

**중요 클래스:**
- `DcuApp`: 메인 애플리케이션 클래스
  - `_connect()`: DCU 연결
  - `_send_simple()`: 단순 명령 전송
  - `_send_rmu_info()`: RMU 정보 요청
  - `_send_rmu_target()`: RMU 대상 명령 전송
  - `_process_frame()`: 수신 프레임 처리
  - `_auto_ack()`: 자동 ACK 전송

#### 3. `client.py` - TCP 클라이언트 (142 lines)

DCU에 연결하는 클라이언트:
- 비동기 소켓 통신 (별도 스레드)
- 자동 재연결 지원
- 프레임 송수신

#### 4. `server.py` - TCP 서버 (202 lines)

FEP 서버:
- DCU 연결 수락
- 단일 클라이언트 연결 (현재)
- 비동기 처리

#### 5. `service_mode.py` - 서비스 모드 (498 lines)

백그라운드 서비스:
- 자동 재연결
- 설정 파일 기반 운영
- 로그 자동 저장

#### 6. `system_arch.py` - 시스템 아키텍처 (697 lines)

모듈형 아키텍처:
- `FepServer`: FEP 서버 래퍼
- `DcuController`: DCU 제어 클라이언트
- `SessionManager`: 세션 관리
- `DataCollector`: 데이터 수집
- `SqliteDataStore`: SQLite 저장소
- `ApiServer`: REST API 서버 (HTTP)
- `IntegratedMeteringSystem`: 통합 시스템

## 프로토콜 상세

### 명령어 목록

#### 요청 명령어 (FEP → DCU)
| Code | Name | Description | Payload |
|------|------|-------------|---------|
| 0x42 | DCU_INFO_REQUEST | DCU 정보 요청 | 없음 |
| 0x43 | DCU_CONFIGURE | DCU 설정 | 27 bytes (시간, IP, Port 등) |
| 0x44 | RMU_INFO_REQUEST | RMU 정보 요청 | 2 bytes (RCU, TCU) |
| 0x45 | RMU_CONFIGURE | RMU 설정 | 10 bytes (설정 데이터) |
| 0x46 | RMU_LIST_REQUEST | RMU 목록 요청 | 없음 |
| 0x47 | CURRENT_READING_REQUEST | 현재 검침값 요청 | 2 bytes (RCU, TCU) |
| 0x48 | SAVED_READING_REQUEST | 저장 검침값 요청 | 2 bytes (RCU, TCU) |
| 0x49 | PERIODIC_READING_REQUEST | 주기 검침값 요청 | 2 bytes (RCU, TCU) |
| 0x4A | EVENT_REQUEST | 이벤트 요청 | 가변 |
| 0x4B | RMU_PULSE_INIT | 펄스 초기화 | 8 bytes |
| 0x4C | MICRO_TEMP_SET | 온도 설정 | 가변 |

#### 응답 명령어 (DCU → FEP)
| Code | Name | Description |
|------|------|-------------|
| 0x41 | ACK | 확인 |
| 0x61 | NACK | 거부 |
| 0x62 | DCU_INFO_RESPONSE | DCU 정보 |
| 0x64 | RMU_INFO_RESPONSE | RMU 정보 |
| 0x66 | RMU_LIST_RESPONSE | RMU 목록 |
| 0x67 | CURRENT_READING_RESPONSE | 현재 검침값 |
| 0x68 | SAVED_READING_RESPONSE | 저장 검침값 |
| 0x69 | PERIODIC_READING_RESPONSE | 주기 검침값 |
| 0x6A | EVENT_NOTIFICATION | 이벤트 알림 |
| 0x6C | MICRO_TEMP_INFO | 온도 정보 |

### 계량기 타입

| Code | Name | Description |
|------|------|-------------|
| 0x01 | Electric (EM) | 전기 계량기 |
| 0x02 | Water (WM) | 수도 계량기 |
| 0x04 | Hot Water (HM) | 온수 계량기 |
| 0x08 | Gas (GM) | 가스 계량기 |
| 0x10 | Heat (CM) | 열량 계량기 |

**비트 마스크로 동작**: 여러 타입 조합 가능 (예: 0x03 = 전기 + 수도)

### M-BUS 프로토콜

계량 데이터는 M-BUS 프로토콜 형식:
```
[Meter Type] [DIF] [VIF] [Value...] [Status]

- DIF (Data Information Field): 데이터 타입 및 길이
- VIF (Value Information Field): 값 단위 및 스케일
- Value: BCD 인코딩된 값
- Status: 상태 코드 (선택)
```

**VIF 해석:**
- `0x00-0x07`: 에너지 (Wh), exponent = (vif & 0x07) - 3
- `0x20-0x27`: 부피 (m³), exponent = (vif & 0x07) - 6
- `0x50-0x53`: 온도 (°C), exponent = (vif & 0x03) - 3

## 데이터 흐름

### 전형적인 시퀀스

```
1. 연결 및 DCU 정보 조회
   FEP → DCU: DCU_INFO_REQUEST (0x42)
   DCU → FEP: DCU_INFO_RESPONSE (0x62)
   FEP → DCU: ACK (0x41)

2. RMU 목록 조회
   FEP → DCU: RMU_LIST_REQUEST (0x46)
   DCU → FEP: RMU_LIST_RESPONSE (0x66) [RMU ID 목록]
   FEP → DCU: ACK (0x41)

3. 특정 RMU 정보 조회
   FEP → DCU: RMU_INFO_REQUEST (0x44) + [RCU=1, TCU=5]
   DCU → FEP: RMU_INFO_RESPONSE (0x64) [RMU 상세 정보]
   FEP → DCU: ACK (0x41)

4. 현재 검침값 조회
   FEP → DCU: CURRENT_READING_REQUEST (0x47) + [RCU=1, TCU=5]
   DCU → FEP: CURRENT_READING_RESPONSE (0x67) [계량 데이터]
   FEP → DCU: ACK (0x41)

5. 주기적 검침 (DCU에서 자동 전송)
   DCU → FEP: PERIODIC_READING_RESPONSE (0x69) [계량 데이터]
   FEP → DCU: ACK (0x41)
```

## 개발 가이드라인

### 새로운 기능 추가 시

1. **프로토콜 확장**
   - `protocol.py`의 `Command` enum에 추가
   - 필요시 `_FRAME_HANDLERS`에 파서 함수 등록
   - 페이로드 구조 문서화

2. **GUI 기능 추가**
   - `app.py`의 `_build_ui()`에서 UI 요소 추가
   - 이벤트 핸들러 메서드 작성
   - `_process_frame()`에서 응답 처리 로직 추가

3. **데이터 저장**
   - `system_arch.py`의 `DataStore` 활용
   - SQLite 테이블 스키마 추가 (필요시)
   - `DataCollector`에 처리 로직 추가

### 코드 스타일

- **타입 힌트**: 모든 함수에 타입 힌트 사용
- **Docstring**: 복잡한 함수는 docstring 추가
- **에러 처리**: 네트워크 I/O는 항상 try-except
- **로깅**: 중요 이벤트는 로그 파일에 기록
- **스레드 안전성**: GUI 업데이트는 메인 스레드에서

### 테스트 방법

1. **로컬 테스트**
   ```bash
   # 서비스 모드 실행 (백그라운드)
   python src/service_mode.py

   # GUI 실행
   python src/app.py
   ```

2. **설정 파일** (`FepServer_init.ini`)
   ```ini
   [connection]
   host = 127.0.0.1
   port = 15000
   did = 0x0001
   sid = 0x0000
   rcu = 0
   tcu = 0
   fep_ip = 127.0.0.1
   fep_port = 9008
   ```

3. **로그 확인**
   - `Login.txt`: DCU 로그인 이력
   - `YYYYMMDD_data.txt`: 프레임 송수신 로그

## 일반적인 작업 시나리오

### 시나리오 1: 새로운 명령어 추가

```python
# 1. protocol.py에 명령어 추가
class Command(enum.IntEnum):
    ...
    NEW_REQUEST = 0x50
    NEW_RESPONSE = 0x70

# 2. 파서 함수 작성
def _handle_new_response(frame: Frame) -> Dict[str, Any]:
    data = frame.data
    # 파싱 로직
    return {"command": "new response", "value": ...}

# 3. 핸들러 등록
_FRAME_HANDLERS[Command.NEW_RESPONSE] = _handle_new_response

# 4. GUI에서 사용
def _send_new_request(self):
    transport = self._get_active_transport()
    did = self._resolve_did(...)
    sid = self._resolve_sid(did)
    payload = b"..."  # 필요한 데이터
    self._send_command(transport, Command.NEW_REQUEST, payload, did=did, sid=sid)
```

### 시나리오 2: 데이터 시각화 추가

```python
# app.py에 matplotlib 통합
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class DcuApp:
    def _build_ui(self):
        # 기존 UI ...

        # 차트 프레임 추가
        chart_frame = ttk.LabelFrame(main, text="실시간 차트")
        chart_frame.pack(fill=tk.BOTH, expand=True)

        # Matplotlib Figure 생성
        self.fig, self.ax = plt.subplots()
        self.canvas = FigureCanvasTkAgg(self.fig, chart_frame)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _update_chart(self, data):
        self.ax.clear()
        self.ax.plot(data['time'], data['value'])
        self.canvas.draw()
```

### 시나리오 3: REST API 활용

```python
# system_arch.py의 ApiServer 사용
from system_arch import IntegratedMeteringSystem, SystemConfig

config = SystemConfig(
    fep_host="0.0.0.0",
    fep_port=9008,
    dcu_host="127.0.0.1",
    dcu_port=15000,
    api_host="127.0.0.1",
    api_port=8080,
)

system = IntegratedMeteringSystem(config)
system.start()

# API 엔드포인트:
# GET  http://localhost:8080/status
# POST http://localhost:8080/commands/current-reading
#      {"rcu": 1, "tcu": 5}
# POST http://localhost:8080/commands/rmu-info
#      {"rcu": 1, "tcu": 5}
```

## 디버깅 팁

### 1. 프레임 로그 확인
```bash
# 최신 데이터 로그 확인
tail -f $(ls -t *_data.txt | head -1)
```

로그 형식:
```
[2025-11-15 12:34:56] DEBUG - SEND[12] E1 10 00 01 00 00 06 42 00 E2
[2025-11-15 12:34:57] DEBUG - RECV[45] E1 10 00 01 00 01 29 62 ...
[2025-11-15 12:34:57] INFO  - CMD - 62 B
[2025-11-15 12:34:57] INFO  - DCU ID     : 1
[2025-11-15 12:34:57] INFO  - ============================[b]
[2025-11-15 12:34:57] INFO  - TIME        : 2025-11-15 12:34:56
[2025-11-15 12:34:57] INFO  - F/W VER     : V1.0
```

### 2. Checksum 오류
- `calc_checksum()` 함수 확인
- `CHECKSUM_PRIMARY` (0x00) 또는 `CHECKSUM_FALLBACK` (0xFF) 중 하나 사용
- DLE escape 전의 raw 데이터로 계산

### 3. DLE Escaping 문제
- `apply_dle()` 함수: 인코딩
- `FrameDecoder.feed()`: 디코딩
- SOF/EOF/DLE만 escape 대상

### 4. M-BUS 파싱 오류
- `resolve_data_length()`: DIF → 데이터 길이
- `interpret_vif()`: VIF → 단위 및 스케일
- `decode_bcd_digits()`: BCD → 숫자

## 중요 상수 및 설정

### 프로토콜 상수
```python
SOF = 0xE1                    # Start of Frame
EOF = 0xE2                    # End of Frame
DLE = 0x10                    # Data Link Escape
DLE_OFFSET = 0x10             # DLE escape offset
DEFAULT_VERSION = 0x10        # Protocol version
CHECKSUM_PRIMARY = 0x00       # Primary checksum initial
CHECKSUM_FALLBACK = 0xFF      # Fallback checksum initial
```

### 기본 포트
```python
FEP_PORT = 9008              # FEP 서버 포트
DCU_PORT = 15000             # DCU 포트 (예시)
API_PORT = 8080              # REST API 포트
```

### 타임아웃
```python
SOCKET_TIMEOUT = 0.5         # 소켓 타임아웃 (초)
CONNECTION_TIMEOUT = 5.0     # 연결 타임아웃 (초)
RECONNECT_DELAY = 5.0        # 재연결 대기 시간 (초)
```

## 알려진 제한사항

1. **단일 클라이언트 연결**: FEP 서버는 현재 하나의 DCU만 연결 가능
2. **GUI 성능**: 대량 데이터 시 Tkinter UI가 느려질 수 있음
3. **에러 처리**: 일부 예외 상황 처리 미흡
4. **테스트 커버리지**: 단위 테스트 부재

## 개선 아이디어

### 단기
- [ ] TreeView로 RCU/TCU 목록 표시
- [ ] SQLite DB 통합 강화
- [ ] 데이터 export (CSV, Excel)
- [ ] 에러 처리 개선

### 중기
- [ ] PyQt5로 마이그레이션
- [ ] 멀티 DCU 지원
- [ ] 웹 대시보드
- [ ] 보고서 생성 (PDF)

### 장기
- [ ] 클라우드 연동
- [ ] 머신러닝 이상 감지
- [ ] 모바일 앱
- [ ] 실시간 알람

## 자주 묻는 질문

### Q: RMU와 TCU의 차이는?
A: RMU = RCU + TCU. RCU는 원격 수집 장치, TCU는 말단 계량기 장치입니다. RMU는 둘을 조합한 개념입니다.

### Q: SID=DCU 모드란?
A: SID (Source ID)를 DID (Destination ID)와 동일하게 설정하는 모드입니다. GUI에서 기본 활성화되어 있습니다.

### Q: Auto ACK는 무엇인가?
A: 응답 프레임 수신 시 자동으로 ACK (0x41)를 전송하는 기능입니다. 프로토콜 규격에 따라 ACK 전송이 필요할 때 사용합니다.

### Q: DLE Escaping이 필요한 이유는?
A: 프레임 데이터에 SOF/EOF가 포함되면 프레임 경계 인식이 잘못될 수 있습니다. DLE로 escape하여 프레임 구조를 보호합니다.

### Q: Checksum이 두 가지인 이유는?
A: 호환성을 위해 Primary (0x00)와 Fallback (0xFF) 두 가지 초기값을 지원합니다. `Frame.ensure_checksum()`에서 둘 다 확인합니다.

### Q: M-BUS 프로토콜이란?
A: 유럽 계량기 표준 프로토콜로, DIF/VIF를 사용하여 계량 데이터를 인코딩합니다. BCD (Binary-Coded Decimal)로 값을 표현합니다.

## 참고 자료

### 내부 문서
- `plan.md`: 개발 계획
- `README.md`: 프로젝트 소개
- `컴파일방법.txt`: 실행 방법

### 외부 자료
- M-BUS 프로토콜: https://m-bus.com/
- Tkinter 문서: https://docs.python.org/3/library/tkinter.html
- asyncio: https://docs.python.org/3/library/asyncio.html

## 코드 예제

### 프레임 생성 예제
```python
from dcutools import FrameEncoder, Command

encoder = FrameEncoder(version=0x10, did=0x0001, sid=0x0000)

# DCU 정보 요청
frame = encoder.build(Command.DCU_INFO_REQUEST, b"")
# → b'\xe1\x10\x00\x01\x00\x00\x06\x42\x59\xe2'

# RMU 정보 요청
frame = encoder.build(
    Command.RMU_INFO_REQUEST,
    b"\x01\x05",  # RCU=1, TCU=5
    did=0x0001,
    sid=0x0000
)
```

### 프레임 파싱 예제
```python
from dcutools import FrameDecoder, parse_frame, PacketParser

decoder = FrameDecoder()
parser = PacketParser()

# 수신 데이터
data = b'\xe1\x10\x00\x01\x00\x01\x29\x62...\xe2'

# 디코딩
frames = decoder.feed(data)
for frame_bytes in frames:
    frame = parse_frame(frame_bytes)
    parsed = parser.parse(frame)
    print(f"Command: {frame.cmd:02X}")
    print(f"Parsed: {parsed}")
```

### GUI 이벤트 처리 예제
```python
class DcuApp:
    def _process_frame(self, frame: Frame, transport: Transport):
        # 프레임 수신 시 호출
        if frame.cmd == Command.CURRENT_READING_RESPONSE:
            parsed = self.packet_parser.parse(frame)
            rmu_id = parsed.get("rmu_id", {})
            dumps = parsed.get("dumps", [])

            # UI 업데이트
            for dump in dumps:
                interp = dump.get("interpreted", {})
                value = interp.get("value", 0)
                unit = interp.get("unit", "")
                print(f"Value: {value} {unit}")
```

## Claude AI 작업 시 유의사항

### 코드 수정 시
1. **타입 힌트 유지**: 기존 타입 힌트 스타일 유지
2. **에러 처리 추가**: 네트워크 I/O는 항상 try-except
3. **로깅 추가**: 중요 이벤트는 `_log()` 또는 `_log_text()` 사용
4. **스레드 안전성**: GUI 업데이트는 이벤트 큐 사용
5. **하위 호환성**: 기존 설정 파일 포맷 유지

### 테스트 작성 시
1. **단위 테스트**: `pytest` 사용
2. **프레임 테스트**: 실제 DCU 프레임 사용
3. **에지 케이스**: DLE escaping, checksum 오류 등

### 문서화 시
1. **Docstring**: Google 스타일
2. **타입 힌트**: 모든 public 함수
3. **예제 코드**: 복잡한 기능은 예제 제공

## 버전 정보

- **프로토콜 버전**: 0x10
- **애플리케이션 버전**: 1.0
- **Python 요구사항**: 3.9+
- **주요 의존성**: 없음 (표준 라이브러리만 사용)

## 라이선스 및 저작권

> 필요 시 여기에 라이선스 정보 추가

---

**마지막 업데이트**: 2025-11-15
**문서 버전**: 1.0
**작성자**: DCUTool Development Team
