# Secure Coding

## Tiny Secondhand Shopping Platform.

You should add some functions and complete the security requirements.

## requirements

if you don't have a miniconda(or anaconda), you can install it on this url. - https://docs.anaconda.com/free/miniconda/index.html

```
git clone https://github.com/ugonfor/secure-coding
conda env create -f enviroments.yaml
```

## usage

run the server process.

```
python app.py
```

if you want to test on external machine, you can utilize the ngrok to forwarding the url.
```
# optional
sudo snap install ngrok
ngrok http 5000
```

# 보안 개선 사항 문서

## Socket.IO 채팅 기능 보안 강화

### 1. 입력 유효성 검사 (Input Validation)
- 메시지 데이터 구조 검증
  - 입력이 dictionary 형태인지 확인
  - 필수 필드 'content' 존재 여부 확인
- 메시지 내용 검증
  - 문자열 타입 검사
  - 최대 길이 제한 (1000자)
- 구현 위치: `handle_message()` 함수

### 2. Rate Limiting
- 사용자별 메시지 전송 제한
  - 초당 최대 1개의 메시지만 허용
  - 전역 딕셔너리를 사용하여 사용자별 마지막 메시지 전송 시간 추적
- DoS 공격 방지
- 구현 위치: `handle_message()` 함수, 전역 변수 `message_timestamps`

### 3. XSS 방지
- 메시지 내용 HTML 이스케이프 처리
- `markupsafe.escape` 함수 사용
- 악성 스크립트 삽입 공격 방지
- 구현 위치: `handle_message()` 함수의 메시지 전송 부분

### 4. 기존 보안 기능
- 세션 기반 인증
  - 모든 소켓 이벤트에서 세션의 `user_uuid` 확인
- 사용자 존재 여부 검증
  - 데이터베이스에서 사용자 정보 확인
- 연결 및 연결 해제 이벤트 처리
  - 적절한 권한 검증
  - 시스템 메시지 브로드캐스트

## 보안 강화 효과
1. 무분별한 메시지 전송 방지
2. 서비스 안정성 향상
3. XSS 공격으로부터 보호
4. 인증된 사용자만의 접근 보장

## 향후 개선 가능 사항
1. 메시지 내용 필터링 (비속어, 스팸 등)
2. IP 기반 Rate Limiting 추가
3. 메시지 암호화
4. WebSocket 연결 보안 강화 (SSL/TLS)

## UI/UX 보안 개선

### 1. 관리자 계정 식별성 강화
- 관리자 로그인 시 눈에 띄는 경고 메시지 표시
- 빨간색 배경과 흰색 텍스트로 시각적 강조
- "⚠️ 관리자 계정을 사용중입니다." 메시지로 명확한 상태 전달
- 목적: 관리자가 권한이 있는 계정 사용 중임을 인지하도록 하여 실수 방지

## 채팅 시스템 개선 사항

### 1. 송금 요청 시스템 강화
- 송금 요청 확인 모달 추가
  - 요청 금액 재확인 기능
  - 실수로 인한 잘못된 금액 요청 방지
- 송금 요청 메시지 개선
  - 요청자 정보 명확히 표시
  - 시간 정보 한국어 형식으로 표시
  - 금액 천 단위 구분자 적용

### 2. 송금 처리 보안 강화
- 송금 금액 유효성 검사 추가
  - 음수 금액 전송 방지
  - 잔액 초과 송금 방지
  - 요청 금액과 일치 여부 확인
- 송금 확인 모달 구현
  - 현재 잔액 표시
  - 송금 금액 재확인
  - 실수로 인한 잘못된 송금 방지

### 3. 채팅방 기능 개선
- 시스템 메시지 표시 방식 개선
  - 중앙 정렬로 가시성 향상
  - 배경색 차별화로 구분성 강화
  - 메시지 종류별 스타일 적용
- 자동 스크롤 기능 추가
  - 새 메시지 수신 시 자동 스크롤
  - 사용자 편의성 향상

### 4. 사용자 인터페이스 개선
- 채팅방 헤더 개선
  - 상품명 표시
  - 상대방 정보 표시
  - 나가기 버튼 추가
- 메시지 스타일 개선
  - 사용자별 메시지 색상 구분
  - 시간 표시 형식 통일
  - 가독성 향상을 위한 여백 조정

### 5. 오류 처리 강화
- 상세한 오류 메시지 제공
  - 송금 실패 사유 명확히 표시
  - 잔액 부족 시 즉각적인 알림
  - 요청 금액 불일치 시 경고
- 실시간 유효성 검사
  - 입력값 즉시 검증
  - 오류 상황 즉시 피드백




