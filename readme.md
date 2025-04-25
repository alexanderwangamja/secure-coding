# Secure Shopping Platform

A secure secondhand shopping platform built with Flask, featuring real-time chat, secure payment system, and comprehensive security measures.

## Features

- User authentication and authorization
- Real-time chat system using Socket.IO
- Secure payment and transfer system
- Product listing and management
- Admin dashboard
- Report system for users and products
- Comprehensive security measures

## Prerequisites

- Linux environment
- Miniconda/Anaconda
- Python 3.8+
- Git

## Installation

1. Clone the repository:
```bash
git clone https://github.com/alexanderwangamja/secure-coding
cd secure-coding
```

2. Create and activate Conda environment:
```bash
conda env create -f environment.yaml
conda activate secure-coding
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

Required packages in requirements.txt:
```
flask==2.0.1
flask-socketio==5.1.1
flask-cors==3.0.10
flask-wtf==0.15.1
python-dotenv==0.19.0
werkzeug==2.0.1
markupsafe==2.0.1
```

4. Set up environment variables:
Create a `.env` file in the project root with:
```
ADMIN_PASSWORD=your_admin_password
SECRET_KEY=your_secret_key
DEFAULT_INIT_PASSWORD=default_password
```

## Usage

1. Initialize and run the server:
```bash
python app_final_complete.py
```

2. Access the application:
- Local: `http://localhost:5000`
- For external access (optional):
```bash
sudo snap install ngrok
ngrok http 5000
```
## 구현된 기능
사용자 인증 및 계정 관리
회원가입: 아이디/비밀번호 유효성 검증 (길이, 문자 제한)
로그인: 5회 실패 시 5분간 잠금
비밀번호 해시화 저장 (Werkzeug security)
세션 관리: 1시간 후 자동 만료
계정 삭제 기능
관리자 기능
관리자 계정 자동 생성 (.env 파일의 ADMIN_PASSWORD 사용)
사용자 관리: 계정 정지/해제, 비밀번호 초기화
상품 관리: 차단/차단해제, 삭제
신고 내역 관리 및 처리
상품 관리
상품 등록/수정/삭제
이미지 업로드 (확장자 검증)
가격 설정 (무료/유료)
상품 검색 기능
채팅 시스템
실시간 1:1 채팅 (Socket.IO)
전역 채팅 (최근 100개 메시지 유지)
초당 1개 메시지로 제한 (Rate limiting)
채팅방 생성/삭제
결제 시스템
잔액 충전 (10000, 30000, 50000, 100000원)
송금 기능 (채팅방 내에서만 가능)
거래 내역 기록
잔액 검증 및 트랜잭션 처리
신고 시스템
사용자 신고: 5회 누적 시 계정 정지
상품 신고: 3회 누적 시 상품 차단
신고 내역 조회
신고 처리 (관리자)
보안 기능
CSRF 토큰 검증
XSS 방지 (HTML 이스케이프)
SQL 인젝션 방지 (파라미터화된 쿼리)
안전한 파일 업로드
세션 보안 설정 (HttpOnly, Secure, SameSite)
데이터베이스 관리
UUID 기반 식별자 사용
자동 DB 초기화 및 테이블 생성
트랜잭션 처리
연결 관리 및 정리

## Implemented Security Features

1. User Authentication & Session Management
- Password hashing using Werkzeug's security functions
- Session-based authentication with 1-hour expiration
- CSRF protection using Flask-WTF
- Login attempt rate limiting (5 attempts per 5 minutes)
- Secure session cookie settings (HttpOnly, Secure flags, SameSite)

2. Input Validation & XSS Prevention
- Server-side validation for user registration
  - Username: 2-20 characters, alphanumeric and underscore only
  - Password: Minimum 8 characters, must include letters and numbers
- HTML escaping using MarkupSafe
- Secure file upload handling with extension validation

3. Chat Security
- Rate limiting: Maximum 1 message per second per user
- Session-based authentication for WebSocket connections
- Input sanitization for chat messages

4. Payment System Security
- Transaction verification and logging
- Balance validation before transfers
- Atomic database transactions for payment operations
- Secure payment request and confirmation system

5. Admin Security Features
- Protected admin routes and functions
- User suspension system after 5 reports
- Product blocking system after 3 reports
- Secure password reset functionality

6. Database Security
- Parameterized SQL queries to prevent SQL injection
- UUID-based identification for all entities
- Proper database connection handling and cleanup

## Directory Structure

```
secure-coding/
├── app_final_complete.py    # Main application file
├── static/                  # Static files (CSS, JS, images)
├── templates/              # HTML templates
├── uploads/               # User uploaded files
├── market.db             # SQLite database
├── requirements.txt      # Python dependencies
├── environment.yaml      # Conda environment file
└── .env                 # Environment variables
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Flask and its extensions
- Socket.IO for real-time communication
- SQLite for database management
- Bootstrap for frontend styling

