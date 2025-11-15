# DCU-RCU-TCU 데이터 통신 GUI 프로그램 개발 계획

## 프로젝트 개요

DCU(Data Collection Unit)를 통해 RCU(Remote Collection Unit)를 거쳐 TCU(Terminal Collection Unit) 데이터를 읽고 설정하는 GUI 프로그램입니다.

### 시스템 아키텍처

```
FEP (Frontend Processor) ←→ DCU ←→ RCU ←→ TCU
     ↓
  GUI 프로그램
```

- **FEP**: 서버 역할, DCU로부터 연결 수락
- **DCU**: 데이터 수집 장치, RCU와 통신
- **RCU**: 원격 수집 장치, 여러 TCU 관리
- **TCU**: 말단 수집 장치, 실제 계량기 데이터 수집

## 현재 구현 상태

### 완료된 기능

1. **프로토콜 레이어** (`src/dcutools/protocol.py`)
   - Frame 인코딩/디코딩 (SOF, EOF, DLE escaping)
   - Checksum 검증
   - Command 정의 (15개 명령어)
   - M-BUS 프로토콜 파싱
   - BCD 인코딩/디코딩

2. **통신 레이어**
   - `client.py`: DCU TCP 클라이언트 (비동기)
   - `server.py`: FEP TCP 서버 (비동기)
   - `transport.py`: 공통 인터페이스

3. **GUI 애플리케이션** (`src/app.py`)
   - Tkinter 기반 GUI
   - DCU 연결/제어
   - RMU(RCU+TCU) 정보 조회
   - 실시간 계량 데이터 조회
   - 주기적 데이터 수집
   - DCU/RMU 설정
   - 터미널 모드 (커스텀 명령 전송)
   - 데이터 로깅 (Login.txt, {date}_data.txt)

4. **서비스 모드** (`src/service_mode.py`)
   - 자동 재연결
   - 백그라운드 데이터 수집
   - 설정 파일 기반 운영

5. **시스템 아키텍처** (`src/system_arch.py`)
   - 모듈형 설계
   - REST API 서버
   - SQLite 데이터 저장
   - Session 관리

### 지원 프로토콜 명령어

#### 요청 명령어 (FEP → DCU)
- `0x42` DCU_INFO_REQUEST: DCU 정보 요청
- `0x43` DCU_CONFIGURE: DCU 설정
- `0x44` RMU_INFO_REQUEST: RMU 정보 요청
- `0x45` RMU_CONFIGURE: RMU 설정
- `0x46` RMU_LIST_REQUEST: RMU 목록 요청
- `0x47` CURRENT_READING_REQUEST: 현재 검침값 요청
- `0x48` SAVED_READING_REQUEST: 저장된 검침값 요청
- `0x49` PERIODIC_READING_REQUEST: 주기적 검침값 요청
- `0x4A` EVENT_REQUEST: 이벤트 요청
- `0x4B` RMU_PULSE_INIT: 펄스 초기화
- `0x4C` MICRO_TEMP_SET: 온도 설정

#### 응답 명령어 (DCU → FEP)
- `0x41` ACK: 확인
- `0x61` NACK: 거부
- `0x62` DCU_INFO_RESPONSE: DCU 정보
- `0x64` RMU_INFO_RESPONSE: RMU 정보
- `0x66` RMU_LIST_RESPONSE: RMU 목록
- `0x67` CURRENT_READING_RESPONSE: 현재 검침값
- `0x68` SAVED_READING_RESPONSE: 저장된 검침값
- `0x69` PERIODIC_READING_RESPONSE: 주기적 검침값
- `0x6A` EVENT_NOTIFICATION: 이벤트 알림
- `0x6C` MICRO_TEMP_INFO: 온도 정보

### 지원 계량기 타입

- **전기 (EM)**: 0x01
- **수도 (WM)**: 0x02
- **온수 (HM)**: 0x04
- **가스 (GM)**: 0x08
- **열량 (CM)**: 0x10

## 개발 계획

### Phase 1: GUI 개선 및 최적화 (1-2주)

#### 1.1 UI/UX 개선
- [ ] 메뉴바 추가 (파일, 설정, 도움말)
- [ ] 상태바 개선 (연결 상태, 마지막 통신 시간)
- [ ] 테마 지원 (라이트/다크 모드)
- [ ] 아이콘 및 이미지 추가
- [ ] 반응형 레이아웃

#### 1.2 RCU/TCU 관리 기능 강화
- [ ] RCU/TCU 목록 TreeView 추가
- [ ] 다중 TCU 동시 조회
- [ ] 자동 스캔 기능 (RCU/TCU 검색)
- [ ] 즐겨찾기 기능

#### 1.3 데이터 시각화
- [ ] 실시간 그래프 (matplotlib 통합)
- [ ] 히스토리 차트
- [ ] 통계 정보 표시
- [ ] 데이터 비교 기능

### Phase 2: 데이터 관리 기능 (2-3주)

#### 2.1 데이터베이스 통합
- [ ] SQLite 연동 (system_arch.py 활용)
- [ ] 검침 이력 저장
- [ ] DCU/RMU 설정 이력
- [ ] 이벤트 로그 저장

#### 2.2 데이터 내보내기/가져오기
- [ ] CSV 내보내기
- [ ] Excel 내보내기
- [ ] JSON 내보내기
- [ ] 데이터 가져오기 기능

#### 2.3 보고서 기능
- [ ] 일일/주간/월간 보고서
- [ ] PDF 생성
- [ ] 이메일 전송 기능
- [ ] 자동 보고서 생성 스케줄러

### Phase 3: 고급 기능 (2-3주)

#### 3.1 자동화 기능
- [ ] 스케줄러 (정기 검침)
- [ ] 알람 설정 (임계값 초과 시)
- [ ] 자동 백업
- [ ] 이벤트 트리거

#### 3.2 멀티 DCU 지원
- [ ] 여러 DCU 동시 연결
- [ ] DCU 간 전환
- [ ] 통합 대시보드
- [ ] DCU 그룹 관리

#### 3.3 원격 제어
- [ ] REST API 서버 (system_arch.py 활용)
- [ ] 웹 인터페이스
- [ ] 모바일 앱 연동
- [ ] 원격 모니터링

### Phase 4: 안정성 및 성능 (1-2주)

#### 4.1 에러 처리
- [ ] 연결 실패 재시도 로직 강화
- [ ] 타임아웃 처리 개선
- [ ] 에러 로그 상세화
- [ ] 사용자 친화적 에러 메시지

#### 4.2 성능 최적화
- [ ] 대용량 데이터 처리
- [ ] 메모리 사용량 최적화
- [ ] 응답 시간 개선
- [ ] 비동기 처리 강화

#### 4.3 테스트
- [ ] 단위 테스트 작성
- [ ] 통합 테스트
- [ ] 부하 테스트
- [ ] 사용자 시나리오 테스트

### Phase 5: 배포 및 문서화 (1주)

#### 5.1 패키징
- [ ] PyInstaller로 실행 파일 생성
- [ ] 설치 프로그램 제작
- [ ] 자동 업데이트 기능
- [ ] 버전 관리

#### 5.2 문서화
- [ ] 사용자 매뉴얼 작성
- [ ] 개발자 가이드
- [ ] API 문서
- [ ] 튜토리얼 비디오

## 기술 스택

### 현재 사용 중
- **언어**: Python 3.9+
- **GUI**: Tkinter
- **네트워크**: socket (비동기)
- **데이터**: SQLite
- **설정**: configparser

### 추가 검토 사항
- **GUI 프레임워크**: PyQt5/PySide6 (더 풍부한 UI)
- **차트**: matplotlib, plotly
- **데이터 처리**: pandas
- **보고서**: reportlab (PDF)
- **웹 API**: FastAPI (REST API)
- **웹 프론트엔드**: React, Vue.js
- **패키징**: PyInstaller, cx_Freeze

## 파일 구조

```
DCUTool/
├── src/
│   ├── app.py              # GUI 메인 애플리케이션
│   ├── service_mode.py     # 서비스 모드 (백그라운드)
│   ├── system_arch.py      # 시스템 아키텍처 (API, DB)
│   └── dcutools/
│       ├── __init__.py
│       ├── protocol.py     # 프로토콜 구현
│       ├── client.py       # TCP 클라이언트
│       ├── server.py       # TCP 서버
│       └── transport.py    # 공통 인터페이스
├── data/                   # 데이터 저장 디렉토리
│   └── metering.sqlite3    # SQLite DB
├── logs/                   # 로그 파일
│   ├── Login.txt           # 로그인 이력
│   └── YYYYMMDD_data.txt   # 일일 데이터 로그
├── config/
│   └── FepServer_init.ini  # 설정 파일
├── tests/                  # 테스트 코드
├── docs/                   # 문서
├── README.md
├── plan.md                 # 이 파일
└── CLAUDE.md              # AI 컨텍스트 문서

```

## 프로토콜 프레임 구조

```
[SOF] [VER] [DID:2] [SID:2] [LEN] [CMD] [DATA...] [CHK] [EOF]

- SOF: 0xE1 (Start of Frame)
- EOF: 0xE2 (End of Frame)
- DLE: 0x10 (Data Link Escape, for escaping SOF/EOF/DLE in data)
- VER: Version (0x10)
- DID: Destination ID (2 bytes, big-endian)
- SID: Source ID (2 bytes, big-endian)
- LEN: Length of CMD + DATA + CHK
- CMD: Command code
- DATA: Payload
- CHK: Checksum (sum of all bytes from VER to last data byte)
```

## RMU ID 구조

RMU ID는 2바이트로 구성:
- Byte 0: RCU ID
- Byte 1: TCU ID

예: RCU=1, TCU=5 → RMU ID = 0x0105

## 데이터 흐름

### 1. DCU 연결 및 정보 조회
```
FEP → DCU: DCU_INFO_REQUEST (0x42)
DCU → FEP: DCU_INFO_RESPONSE (0x62)
            - Timestamp
            - Firmware version
            - FEP IP/Port
            - DCU IP/Port
            - Send period
            - Log period
            - Retry count
FEP → DCU: ACK (0x41)
```

### 2. RMU 정보 조회
```
FEP → DCU: RMU_INFO_REQUEST (0x44) + [RCU ID, TCU ID]
DCU → FEP: RMU_INFO_RESPONSE (0x64)
            - RMU ID
            - Firmware version
            - Measured at
            - Meter type (전기/수도/온수/가스/열량)
            - Protocol type
            - TX period
FEP → DCU: ACK (0x41)
```

### 3. 현재 검침값 조회
```
FEP → DCU: CURRENT_READING_REQUEST (0x47) + [RCU ID, TCU ID]
DCU → FEP: CURRENT_READING_RESPONSE (0x67)
            - RMU ID
            - Timestamp
            - Meter dumps (DIF, VIF, value)
FEP → DCU: ACK (0x41)
```

## 개발 우선순위

### 높음 (High Priority)
1. GUI 안정성 개선
2. 에러 처리 강화
3. 데이터 저장 기능
4. RCU/TCU 목록 관리

### 중간 (Medium Priority)
1. 데이터 시각화
2. 보고서 생성
3. 자동화 기능
4. REST API

### 낮음 (Low Priority)
1. 웹 인터페이스
2. 모바일 앱
3. 고급 통계 기능
4. 클라우드 연동

## 참고 사항

### 주요 설정 파일
- `FepServer_init.ini`: 연결 설정, DCU/RCU/TCU ID, IP/Port 등

### 로그 파일
- `Login.txt`: DCU 로그인 이력
- `YYYYMMDD_data.txt`: 일일 프레임 로그 (HEX, 파싱 정보)

### 개발 시 주의사항
1. **DLE Escaping**: 프레임 내 SOF/EOF/DLE는 DLE로 escape 필요
2. **Checksum**: VER부터 마지막 데이터까지 합산 (0xFF로 마스크)
3. **SID=DCU 모드**: GUI에서 기본 활성화, SID를 DID와 동일하게 설정
4. **Auto ACK**: 응답 프레임 수신 시 자동 ACK 전송 (설정 가능)
5. **비동기 처리**: 모든 네트워크 I/O는 별도 스레드에서 처리
6. **에러 복구**: 연결 끊김 시 자동 재연결 (service_mode.py)

## 다음 단계

1. **즉시 시작 가능한 작업**:
   - RCU/TCU 목록 TreeView 추가
   - 데이터 시각화 (matplotlib)
   - SQLite DB 연동 강화

2. **계획 중인 작업**:
   - PyQt5로 마이그레이션 검토
   - REST API 서버 통합
   - 웹 대시보드 개발

3. **장기 목표**:
   - 클라우드 연동
   - 머신러닝 기반 이상 감지
   - 모바일 앱 개발

## 버전 이력

- **v1.0** (현재): 기본 GUI, DCU/RMU 제어, 데이터 조회
- **v1.1** (계획): DB 저장, 데이터 시각화
- **v1.2** (계획): REST API, 멀티 DCU
- **v2.0** (계획): 웹 인터페이스, 고급 기능
