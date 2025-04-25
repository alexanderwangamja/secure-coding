import sqlite3
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
import os

def get_db():
    db = sqlite3.connect('market.db')
    db.row_factory = sqlite3.Row
    return db

def migrate_passwords():
    db = get_db()
    cursor = db.cursor()
    
    # 모든 사용자 조회
    cursor.execute("SELECT uuid, password FROM user")
    users = cursor.fetchall()
    
    # 각 사용자의 비밀번호를 해시화
    for user in users:
        # 이미 해시된 비밀번호는 건너뜀 (해시된 비밀번호는 보통 매우 긴 문자열)
        if len(user['password']) < 50:  
            password_hash = generate_password_hash(user['password'])
            cursor.execute(
                "UPDATE user SET password = ? WHERE uuid = ?",
                (password_hash, user['uuid'])
            )
            print(f"Updated password for user {user['uuid']}")
    
    db.commit()
    print("Password migration completed")

if __name__ == '__main__':
    load_dotenv()
    migrate_passwords() 