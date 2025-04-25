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

- Ubuntu WSL or Linux environment
- Miniconda/Anaconda
- Python 3.8+
- Git

## Installation

1. Clone the repository:
```bash
git clone https://github.com/[your-username]/secure-coding
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

