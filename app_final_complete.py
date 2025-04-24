from flask import Flask, render_template, request, redirect, url_for, session, flash, g, jsonify
from flask_socketio import SocketIO, send, join_room, leave_room, emit
from flask_cors import CORS
from functools import wraps
import sqlite3
import uuid
import os
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import re
from markupsafe import escape

# 로그인 필요 데코레이터 정의
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_uuid' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

load_dotenv()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'

# SocketIO 설정
socketio = SocketIO(app, cors_allowed_origins="*")
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 천 단위 구분자를 위한 필터 추가
@app.template_filter('format_price')
def format_price(value):
    return "{:,}".format(value)

# 날짜 형식을 위한 필터 추가
@app.template_filter('format_datetime')
def format_datetime(value):
    if value is None:
        return ""
    return value.strftime('%Y년 %m월 %d일 %H:%M')

# Rate limiting을 위한 전역 변수
message_timestamps = {}  # {user_uuid: last_message_time}

# ✅ 4. 최초 실행 시 admin 계정 자동 생성
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.before_first_request
def startup():
    init_db()  # 반드시 먼저 호출되어야 함
    create_admin_if_not_exists()

# ✅ 5. 파일 확장자 체크 함수
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user (
            uuid TEXT PRIMARY KEY,
            id TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT,
            is_suspended INTEGER DEFAULT 0,
            balance INTEGER DEFAULT 0
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS product (
            uuid TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            price INTEGER NOT NULL,
            image TEXT,
            is_blocked INTEGER DEFAULT 0,
            seller_uuid TEXT NOT NULL,
            is_free INTEGER DEFAULT 0,
            FOREIGN KEY (seller_uuid) REFERENCES user(uuid)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            uuid TEXT PRIMARY KEY,
            sender_uuid TEXT NOT NULL,
            receiver_uuid TEXT NOT NULL,
            amount INTEGER NOT NULL,
            type TEXT DEFAULT 'TRANSFER',
            balance_after INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_uuid) REFERENCES user(uuid),
            FOREIGN KEY (receiver_uuid) REFERENCES user(uuid)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report (
            uuid TEXT PRIMARY KEY,
            reporter_uuid TEXT NOT NULL,
            target_uuid TEXT NOT NULL,
            reason TEXT NOT NULL,
            FOREIGN KEY (reporter_uuid) REFERENCES user(uuid)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_room (
            uuid TEXT PRIMARY KEY,
            product_uuid TEXT NOT NULL,
            buyer_uuid TEXT NOT NULL,
            seller_uuid TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_uuid) REFERENCES product(uuid),
            FOREIGN KEY (buyer_uuid) REFERENCES user(uuid),
            FOREIGN KEY (seller_uuid) REFERENCES user(uuid)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS chat_message (
            uuid TEXT PRIMARY KEY,
            chat_room_uuid TEXT NOT NULL,
            sender_uuid TEXT NOT NULL,
            message_type TEXT NOT NULL,
            content TEXT NOT NULL,
            amount INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (chat_room_uuid) REFERENCES chat_room(uuid),
            FOREIGN KEY (sender_uuid) REFERENCES user(uuid)
        )
    """)
    db.commit()

@app.route('/admin/users')
def admin_users():
    if session.get('user_id') != 'admin':
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT uuid, id, bio, is_suspended FROM user")
    users = cursor.fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/<user_uuid>/reset_password')
def reset_password(user_uuid):
    if session.get('user_id') != 'admin':
        flash('권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    from dotenv import load_dotenv
    load_dotenv()
    reset_password = os.getenv("DEFAULT_INIT_PASSWORD")
    cursor.execute("UPDATE user SET password = ? WHERE uuid = ?", (reset_password, user_uuid))
    db.commit()

    flash(f"비밀번호가 초기화되었습니다. (초기 비밀번호: {reset_password})")
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<user_uuid>/edit_bio', methods=['GET', 'POST'])
def edit_bio(user_uuid):
    if session.get('user_id') != 'admin':
        flash('권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        new_bio = request.form['bio'].strip()
        cursor.execute("UPDATE user SET bio = ? WHERE uuid = ?", (new_bio, user_uuid))
        db.commit()
        flash("소개글이 변경되었습니다.")
        return redirect(url_for('admin_users'))

    cursor.execute("SELECT id, bio FROM user WHERE uuid = ?", (user_uuid,))
    user = cursor.fetchone()
    return render_template("admin_edit_bio.html", user=user, user_uuid=user_uuid)

@app.route('/admin/user/<user_uuid>/unsuspend')
def unsuspend_user(user_uuid):
    if session.get('user_id') != 'admin':
        flash('권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE user SET is_suspended = 0 WHERE uuid = ?", (user_uuid,))
    db.commit()

    flash("해당 사용자의 비활성화 상태가 해제되었습니다.")
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<user_uuid>/reports')
def view_user_reports(user_uuid):
    if session.get('user_id') != 'admin':
        flash('권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM user WHERE uuid = ?", (user_uuid,))
    user = cursor.fetchone()

    cursor.execute("""
        SELECT r.uuid, r.reporter_uuid, r.reason
        FROM report r
        WHERE r.target_uuid = ?
    """, (user_uuid,))
    reports = cursor.fetchall()

    return render_template('admin_user_reports.html', user=user, user_uuid=user_uuid, reports=reports)

@app.route('/admin/user/<user_uuid>/delete_reports', methods=['POST'])
def delete_user_reports(user_uuid):
    if session.get('user_id') != 'admin':
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM report WHERE target_uuid = ?", (user_uuid,))
    db.commit()

    flash("해당 사용자의 모든 신고 기록이 삭제되었습니다.")
    return redirect(url_for('view_user_reports', user_uuid=user_uuid))

@app.route('/admin/products')
def admin_products():
    if session.get('user_id') != 'admin':
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT p.uuid, p.title, p.price, p.is_blocked, u.id as seller
        FROM product p
        JOIN user u ON p.seller_uuid = u.uuid
    """)
    products = cursor.fetchall()

    return render_template("admin_products.html", products=products)

@app.route('/admin/products/blocked')
def admin_blocked_products():
    if session.get('user_id') != 'admin':
        flash('관리자만 접근 가능합니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT p.uuid, p.title, p.price, u.id as seller
        FROM product p
        JOIN user u ON p.seller_uuid = u.uuid
        WHERE p.is_blocked = 1
    """)
    products = cursor.fetchall()

    return render_template("admin_blocked_products.html", products=products)

@app.route('/admin/product/<product_uuid>/delete')
def delete_product(product_uuid):
    if session.get('user_id') != 'admin':
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM product WHERE uuid = ?", (product_uuid,))
    db.commit()

    flash("상품이 삭제되었습니다.")
    return redirect(url_for('admin_products'))

@app.route('/admin/product/<product_uuid>/unblock')
def unblock_product(product_uuid):
    if session.get('user_id') != 'admin':
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE product SET is_blocked = 0 WHERE uuid = ?", (product_uuid,))
    db.commit()

    flash("상품의 차단이 해제되었습니다.")
    return redirect(url_for('admin_blocked_products'))

@app.route('/')
def index():
    if 'user_uuid' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_id = request.form['id']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('비밀번호가 일치하지 않습니다.')
            return redirect(url_for('register'))
            
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ?", (user_id,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_uuid = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (uuid, id, password) VALUES (?, ?, ?)",
                       (user_uuid, user_id, password))
        db.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # 이미 로그인된 사용자 처리
    if 'user_uuid' in session:
        flash('이미 로그인되어 있습니다.')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        user_id = request.form['id']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE id = ? AND password = ?", (user_id, password))
        user = cursor.fetchone()
        if user:
            if user['is_suspended']:
                flash('신고 누적으로 계정이 비활성화되었습니다. 관리자에게 문의하세요.')
                return redirect(url_for('login'))
            session['user_uuid'] = user['uuid']
            session['user_id'] = user['id']
            flash('로그인되었습니다.')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호 오류입니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE uuid = ?", (session['user_uuid'],))
    user = cursor.fetchone()
    
    # 전체 상품 수 조회
    cursor.execute("SELECT COUNT(*) as total FROM product WHERE is_blocked = 0")
    total_count = cursor.fetchone()['total']
    
    # referer를 확인하여 홈 버튼을 통한 접근인지 확인
    is_home_button = request.referrer and 'dashboard' in request.referrer and not request.args.get('q')
    
    # 검색어 가져오기 (홈 버튼으로 접근시 무시)
    query = request.args.get('q', '').strip() if not is_home_button else ''
    
    # 검색 조건에 따른 상품 조회
    if query:
        cursor.execute("""
            SELECT p.*, u.id as seller_id 
            FROM product p 
            JOIN user u ON p.seller_uuid = u.uuid 
            WHERE p.is_blocked = 0 
            AND (p.title LIKE ? OR p.description LIKE ?)
        """, ('%' + query + '%', '%' + query + '%'))
        products = cursor.fetchall()
        search_count = len(products)
        flash(f'검색어 "{query}"에 대한 검색 결과 {search_count}건')
    else:
        cursor.execute("""
            SELECT p.*, u.id as seller_id 
            FROM product p 
            JOIN user u ON p.seller_uuid = u.uuid 
            WHERE p.is_blocked = 0
        """)
        products = cursor.fetchall()

    return render_template('dashboard.html', 
                         user=user, 
                         products=products, 
                         query=query,
                         total_count=total_count)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form['bio']
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()
        confirm_new_password = request.form.get('confirm_new_password', '').strip()

        # 변경사항 추적
        changes = []
        
        # 소개글 변경 확인
        cursor.execute("SELECT bio FROM user WHERE uuid = ?", (session['user_uuid'],))
        user_data = cursor.fetchone()
        current_bio = user_data['bio'] if user_data else None
        
        if bio != current_bio:
            cursor.execute("UPDATE user SET bio = ? WHERE uuid = ?", (bio, session['user_uuid']))
            changes.append("소개글")

        # 비밀번호 변경 로직
        if current_password and new_password:
            cursor.execute("SELECT password FROM user WHERE uuid = ?", (session['user_uuid'],))
            stored_pw = cursor.fetchone()['password']
            
            # 기존 비밀번호 검증을 먼저 수행
            if stored_pw != current_password:
                flash("기존 비밀번호가 일치하지 않습니다.")
                return redirect(url_for('profile'))
            
            # 기존 비밀번호가 일치하는 경우에만 새 비밀번호 검증
            if new_password != confirm_new_password:
                flash("새 비밀번호가 일치하지 않습니다.")
                return redirect(url_for('profile'))
                
            cursor.execute("UPDATE user SET password = ? WHERE uuid = ?", (new_password, session['user_uuid']))
            changes.append("비밀번호")
        elif new_password or confirm_new_password or current_password:  # 비밀번호 필드 중 일부만 입력된 경우
            flash("비밀번호를 변경하려면 모든 필드를 입력해야 합니다.")
            return redirect(url_for('profile'))

        # 변경사항 알림
        if changes:
            if len(changes) == 2:
                flash("소개글과 비밀번호가 변경되었습니다.")
            elif changes[0] == "소개글":
                flash("소개글을 변경했습니다.")
            else:
                flash("비밀번호를 변경했습니다.")

        db.commit()
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE uuid = ?", (session['user_uuid'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user)

@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        is_free = request.form.get('is_free') == 'on'
        price = 0 if is_free else int(request.form['price'])
        
        # 제목 검증 (2글자 이상)
        if len(title) < 2:
            flash('제목은 2글자 이상이어야 합니다.')
            return redirect(url_for('new_product'))
            
        # 설명 검증 (10글자 이상)
        if len(description) < 10:
            flash('설명은 10글자 이상이어야 합니다.')
            return redirect(url_for('new_product'))
            
        # 가격 검증
        if not is_free and (price <= 0 or price > 99999999999):
            flash('가격을 정확히 입력해주세요.')
            return redirect(url_for('new_product'))
            
        image_file = request.files['image']
        image_filename = None
        if image_file and allowed_file(image_file.filename):
            image_filename = secure_filename(str(uuid.uuid4()) + '_' + image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            image_file.save(image_path)
            
        db = get_db()
        cursor = db.cursor()
        product_uuid = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO product (uuid, title, description, price, image, seller_uuid, is_free)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (product_uuid, title, description, price, image_filename, session['user_uuid'], 1 if is_free else 0))
        db.commit()
        flash('등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

@app.route('/my-products')
def my_products():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE seller_uuid = ?", (session['user_uuid'],))
    products = cursor.fetchall()
    return render_template('my_products.html', products=products)

@app.route('/product/<product_uuid>')
def view_product(product_uuid):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE uuid = ?", (product_uuid,))
    product = cursor.fetchone()
    if not product or product['is_blocked']:
        flash('이 상품은 존재하지 않거나 차단되었습니다.')
        return redirect(url_for('dashboard'))
    cursor.execute("SELECT * FROM user WHERE uuid = ?", (product['seller_uuid'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_id = request.form['target_id'].strip()
        reason = request.form['reason'].strip()
        target_type = request.form.get('target_type', 'user')  # 기본값은 user

        if not target_id or not reason:
            flash("신고 대상과 사유를 모두 입력해야 합니다.")
            return redirect(url_for('report'))

        if target_type == 'user':
            # 자기 자신을 신고하는지 확인
            if target_id == session['user_id']:
                flash("자기 자신은 신고할 수 없습니다.")
                return redirect(url_for('report'))

            # target_id로 사용자 찾기
            cursor.execute("SELECT uuid FROM user WHERE id = ?", (target_id,))
            user_row = cursor.fetchone()

            if not user_row:
                flash("존재하지 않는 사용자입니다.")
                return redirect(url_for('report'))

            target_uuid = user_row['uuid']
        else:  # product
            # 상품이 존재하는지 확인
            cursor.execute("SELECT uuid FROM product WHERE uuid = ?", (target_id,))
            product_row = cursor.fetchone()

            if not product_row:
                flash("존재하지 않는 상품입니다.")
                return redirect(url_for('dashboard'))

            target_uuid = target_id

        report_uuid = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (uuid, reporter_uuid, target_uuid, reason) VALUES (?, ?, ?, ?)",
            (report_uuid, session['user_uuid'], target_uuid, reason)
        )
        db.commit()

        # 신고 누적 검사
        check_report_threshold(target_uuid)

        flash("신고가 접수되었습니다.")
        return redirect(url_for('dashboard'))

    # admin을 제외한 모든 사용자 목록 가져오기
    cursor.execute("""
        SELECT id FROM user 
        WHERE id != 'admin' 
        AND uuid != ? 
        ORDER BY id
    """, (session['user_uuid'],))
    users = cursor.fetchall()

    return render_template('report.html', users=users)

@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
        
    target_id = request.form['target']
    amount = int(request.form['amount'])
    
    if amount <= 0:
        flash('송금액은 0보다 커야 합니다.')
        return redirect(url_for('payment'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 송금자 정보 확인
    cursor.execute("SELECT * FROM user WHERE uuid = ?", (session['user_uuid'],))
    sender = cursor.fetchone()
    
    # 수신자 정보 확인
    cursor.execute("SELECT * FROM user WHERE id = ?", (target_id,))
    receiver = cursor.fetchone()
    
    if not receiver:
        flash('존재하지 않는 사용자입니다.')
        return redirect(url_for('payment'))
        
    if receiver['uuid'] == sender['uuid']:
        flash('자기 자신에게는 송금할 수 없습니다.')
        return redirect(url_for('payment'))
        
    # 상품 거래와 관련된 송금인지 확인
    cursor.execute("""
        SELECT * FROM chat_room cr
        JOIN product p ON cr.product_uuid = p.uuid
        WHERE (cr.buyer_uuid = ? AND cr.seller_uuid = ?)
        OR (cr.buyer_uuid = ? AND cr.seller_uuid = ?)
    """, (session['user_uuid'], receiver['uuid'], receiver['uuid'], session['user_uuid']))
    chat_room = cursor.fetchone()
    
    if not chat_room:
        flash('상품 거래 관련 채팅방이 없는 사용자에게는 송금할 수 없습니다.')
        return redirect(url_for('payment'))
        
    if sender['balance'] < amount:
        flash('잔액이 부족합니다.')
        return redirect(url_for('payment'))
        
    try:
        # 거래 기록 생성
        transaction_uuid = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO transactions (uuid, sender_uuid, receiver_uuid, amount, type, balance_after)
            VALUES (?, ?, ?, ?, 'TRANSFER', ?)
        """, (transaction_uuid, sender['uuid'], receiver['uuid'], amount, sender['balance'] - amount))
        
        # 잔액 업데이트
        cursor.execute("UPDATE user SET balance = balance - ? WHERE uuid = ?", 
                      (amount, sender['uuid']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE uuid = ?", 
                      (amount, receiver['uuid']))
        
        db.commit()
        flash(f"{receiver['id']}님께 {amount:,}원을 송금했습니다.")
        
    except Exception as e:
        db.rollback()
        flash('송금 처리 중 오류가 발생했습니다.')
        print(f"Transfer error: {str(e)}")
        
    return redirect(url_for('payment'))

@app.route('/admin/reports')
def view_all_reports():
    if session.get('user_id') != 'admin':
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT r.uuid, r.reason, r.reporter_uuid, r.target_uuid, u.id AS reporter
        FROM report r
        JOIN user u ON r.reporter_uuid = u.uuid
    """)
    reports = cursor.fetchall()

    enriched_reports = []
    for r in reports:
        target_uuid = r['target_uuid'].strip()

        # 사용자 확인
        cursor.execute("SELECT id FROM user WHERE uuid = ?", (target_uuid,))
        user_result = cursor.fetchone()

        if user_result:
            target_display = f"사용자: {user_result['id']}"
        else:
            # 상품 여부 확인
            cursor.execute("SELECT title FROM product WHERE uuid = ?", (target_uuid,))
            product_result = cursor.fetchone()

            if product_result:
                target_display = f"상품: {product_result['title']}"
            else:
                target_display = "❓알 수 없음"

        enriched_reports.append({
            'uuid': r['uuid'],
            'reporter': r['reporter'],
            'reason': r['reason'],
            'target_display': target_display
        })

    return render_template('report_list.html', reports=enriched_reports)

@app.route('/admin/reports/delete_all', methods=['POST'])
def delete_all_reports():
    if session.get('user_id') != 'admin':
        flash('접근 권한이 없습니다.')
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM report")
    db.commit()
    flash("모든 신고 내역이 삭제되었습니다.")
    return redirect(url_for('view_all_reports'))

@app.route('/admin/reports/<report_uuid>/delete', methods=['POST'])
def delete_report(report_uuid):
    if session.get('user_id') != 'admin':
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM report WHERE uuid = ?", (report_uuid,))
    db.commit()
    flash("해당 신고 내역이 삭제되었습니다.")
    return redirect(url_for('view_all_reports'))

@app.route('/my-reports')
def my_reports():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT uuid, target_uuid, reason FROM report
        WHERE reporter_uuid = ?
    """, (session['user_uuid'],))
    reports = cursor.fetchall()
    return render_template('my_reports.html', reports=reports)

def check_report_threshold(target_uuid):
    db = get_db()
    cursor = db.cursor()

    # 해당 대상의 신고 누적 수 확인
    cursor.execute("SELECT COUNT(*) FROM report WHERE target_uuid = ?", (target_uuid,))
    count = cursor.fetchone()[0]

    print(f"[DEBUG] 대상 UUID: {target_uuid}, 신고 횟수: {count}")
    
    if count >= 5:
        cursor.execute("UPDATE user SET is_suspended = 1 WHERE uuid = ?", (target_uuid,))
        db.commit()
        print(f"[INFO] 사용자 {target_uuid}는 신고 {count}회 누적으로 비활성화되었습니다.")

    # 상품 신고 누적 3회 이상인 상품 → 차단
    cursor.execute("""
        SELECT target_uuid FROM report
        WHERE target_uuid IN (SELECT uuid FROM product)
        GROUP BY target_uuid
        HAVING COUNT(*) >= 3
    """)
    for row in cursor.fetchall():
        cursor.execute("UPDATE product SET is_blocked = 1 WHERE uuid = ?", (row['target_uuid'],))

    db.commit()

def create_admin_if_not_exists():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = 'admin'")
    if not cursor.fetchone():
        admin_uuid = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO user (uuid, id, password) VALUES (?, ?, ?)",
            (admin_uuid, 'admin', ADMIN_PASSWORD)
        )
        db.commit()

# 전역 채팅을 위한 이벤트 핸들러
@socketio.on('global_chat')
def handle_global_chat(data):
    if 'user_uuid' not in session:
        return
    
    message = data.get('message', '').strip()
    if not message:
        return
        
    # Rate limiting: 1초당 최대 1개 메시지
    user_uuid = session['user_uuid']
    now = datetime.now()
    if user_uuid in message_timestamps:
        if now - message_timestamps[user_uuid] < timedelta(seconds=1):
            return
    message_timestamps[user_uuid] = now
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM user WHERE uuid = ?", (session['user_uuid'],))
    sender = cursor.fetchone()
    
    if not sender:
        return
    
    # 전역 메시지 전송 (room='global'을 사용)
    response = {
        'sender_uuid': session['user_uuid'],
        'sender_id': sender['id'],
        'message': message,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    socketio.emit('global_chat_message', response, to='global')

# 1:1 채팅을 위한 이벤트 핸들러
@socketio.on('private_chat')
def handle_private_chat(data):
    if 'user_uuid' not in session:
        return
        
    room_uuid = data.get('room_uuid')
    message = data.get('message', '').strip()
    
    if not room_uuid or not message:
        return
        
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 확인
    cursor.execute("""
        SELECT * FROM chat_room 
        WHERE uuid = ? AND (buyer_uuid = ? OR seller_uuid = ?)
    """, (room_uuid, session['user_uuid'], session['user_uuid']))
    
    room = cursor.fetchone()
    if not room:
        return
        
    # 메시지 저장
    message_uuid = str(uuid.uuid4())
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    cursor.execute("""
        INSERT INTO chat_message (uuid, chat_room_uuid, sender_uuid, message_type, content, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (message_uuid, room_uuid, session['user_uuid'], 'text', message, now))
    
    cursor.execute("SELECT id FROM user WHERE uuid = ?", (session['user_uuid'],))
    sender = cursor.fetchone()
    
    db.commit()
    
    # 메시지 전송 (특정 room으로)
    response = {
        'sender_uuid': session['user_uuid'],
        'sender_id': sender['id'],
        'message': message,
        'timestamp': now
    }
    
    socketio.emit('private_chat_message', response, to=room_uuid)

# Socket.IO 이벤트: 전역 채팅방 입장
@socketio.on('join_global')
def on_join_global():
    if 'user_uuid' not in session:
        return
    join_room('global')
    print(f"User {session['user_uuid']} joined global chat")

# Socket.IO 이벤트: 개인 채팅방 입장
@socketio.on('join_private')
def on_join_private(data):
    if 'user_uuid' not in session:
        return
    room = data.get('room')
    if room:
        join_room(room)
        print(f"User {session['user_uuid']} joined private room {room}")

# Socket.IO 이벤트: 채팅방 퇴장
@socketio.on('leave_room')
def on_leave_room(data):
    if 'user_uuid' not in session:
        return
    room = data.get('room')
    if room:
        leave_room(room)
        print(f"User {session['user_uuid']} left room {room}")

@app.route('/delete-account', methods=['GET', 'POST'])
def delete_account():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
    
    # 관리자 계정 삭제 시도 방지
    if session.get('user_id') == 'admin':
        flash("관리자 계정은 삭제할 수 없습니다.")
        return redirect(url_for('profile'))
    
    if request.method == 'POST':
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        
        # 비밀번호 확인
        cursor.execute("SELECT password FROM user WHERE uuid = ?", (session['user_uuid'],))
        user = cursor.fetchone()
        
        if not user or user['password'] != password:
            flash("비밀번호가 일치하지 않습니다.")
            return redirect(url_for('delete_account'))
        
        # 사용자 관련 데이터 삭제
        cursor.execute("DELETE FROM report WHERE reporter_uuid = ? OR target_uuid = ?", 
                      (session['user_uuid'], session['user_uuid']))
        cursor.execute("DELETE FROM product WHERE seller_uuid = ?", (session['user_uuid'],))
        cursor.execute("DELETE FROM user WHERE uuid = ?", (session['user_uuid'],))
        
        db.commit()
        session.clear()
        
        flash("이용해주셔서 감사합니다.")
        return redirect(url_for('index'))
    
    return render_template('delete_account.html')

@app.route('/verify-password', methods=['POST'])
def verify_password():
    if 'user_uuid' not in session:
        return jsonify({'valid': False}), 401

    try:
        data = request.get_json()
        current_password = data.get('current_password', '')

        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT password FROM user WHERE uuid = ?", (session['user_uuid'],))
        user = cursor.fetchone()

        if user and user['password'] == current_password:
            return jsonify({'valid': True})
        return jsonify({'valid': False})
    except Exception as e:
        print(f"Error verifying password: {e}")
        return jsonify({'valid': False, 'error': 'Internal server error'}), 500

@app.route('/chat/start/<product_uuid>', methods=['POST'])
def start_chat(product_uuid):
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 상품 정보 확인
    cursor.execute("SELECT seller_uuid FROM product WHERE uuid = ?", (product_uuid,))
    product = cursor.fetchone()
    if not product:
        flash("존재하지 않는 상품입니다.")
        return redirect(url_for('dashboard'))
        
    # 자신의 상품인지 확인
    if product['seller_uuid'] == session['user_uuid']:
        flash("자신의 상품에는 채팅을 시작할 수 없습니다.")
        return redirect(url_for('view_product', product_uuid=product_uuid))
        
    # 이미 존재하는 채팅방 확인
    cursor.execute("""
        SELECT uuid FROM chat_room 
        WHERE product_uuid = ? AND buyer_uuid = ?
    """, (product_uuid, session['user_uuid']))
    existing_chat = cursor.fetchone()
    
    if existing_chat:
        return redirect(url_for('chat_room', room_uuid=existing_chat['uuid']))
        
    # 새 채팅방 생성
    room_uuid = str(uuid.uuid4())
    cursor.execute("""
        INSERT INTO chat_room (uuid, product_uuid, buyer_uuid, seller_uuid)
        VALUES (?, ?, ?, ?)
    """, (room_uuid, product_uuid, session['user_uuid'], product['seller_uuid']))
    db.commit()
    
    return redirect(url_for('chat_room', room_uuid=room_uuid))

@app.route('/chat/rooms')
def chat_rooms():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 메시지가 있는 채팅방만 조회
    cursor.execute("""
        SELECT DISTINCT
            cr.uuid as room_uuid,
            p.title as product_title,
            p.price as product_price,
            u1.id as buyer_id,
            u2.id as seller_id,
            p.uuid as product_uuid,
            (SELECT cm.content 
             FROM chat_message cm 
             WHERE cm.chat_room_uuid = cr.uuid 
             ORDER BY cm.created_at DESC 
             LIMIT 1) as last_message,
            (SELECT cm.created_at 
             FROM chat_message cm 
             WHERE cm.chat_room_uuid = cr.uuid 
             ORDER BY cm.created_at DESC 
             LIMIT 1) as last_message_time,
            EXISTS (
                SELECT 1 
                FROM chat_message cm 
                WHERE cm.chat_room_uuid = cr.uuid
            ) as has_messages
        FROM chat_room cr
        JOIN product p ON cr.product_uuid = p.uuid
        JOIN user u1 ON cr.buyer_uuid = u1.uuid
        JOIN user u2 ON cr.seller_uuid = u2.uuid
        WHERE (cr.buyer_uuid = ? OR cr.seller_uuid = ?)
        AND EXISTS (
            SELECT 1 
            FROM chat_message cm 
            WHERE cm.chat_room_uuid = cr.uuid
        )
        ORDER BY last_message_time DESC
    """, (session['user_uuid'], session['user_uuid']))
    
    chat_rooms = cursor.fetchall()
    return render_template('chat_rooms.html', chat_rooms=chat_rooms)

@socketio.on('chat_message')
def handle_chat_message(data):
    if 'user_uuid' not in session:
        return
        
    room_uuid = data.get('room_uuid')
    content = data.get('content', '').strip()
    message_type = data.get('type', 'text')  # 기본값은 text
    
    if not room_uuid or not content:
        return
        
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방 확인
    cursor.execute("""
        SELECT * FROM chat_room 
        WHERE uuid = ? AND (buyer_uuid = ? OR seller_uuid = ?)
    """, (room_uuid, session['user_uuid'], session['user_uuid']))
    
    room = cursor.fetchone()
    if not room:
        return
        
    # 메시지 저장
    message_uuid = str(uuid.uuid4())
    now = datetime.now()
    cursor.execute("""
        INSERT INTO chat_message (uuid, chat_room_uuid, sender_uuid, message_type, content, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (message_uuid, room_uuid, session['user_uuid'], message_type, content, now))
    
    cursor.execute("SELECT id FROM user WHERE uuid = ?", (session['user_uuid'],))
    sender = cursor.fetchone()
    
    db.commit()
    
    # 메시지 브로드캐스트
    message = {
        'uuid': message_uuid,
        'sender_id': sender['id'],
        'sender_uuid': session['user_uuid'],
        'content': content,
        'type': message_type,
        'created_at': now.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    socketio.emit('chat_message', message, room=room_uuid)

@socketio.on('join')
def on_join(data):
    if 'user_uuid' not in session:
        return
        
    room = data.get('room')
    if room:
        join_room(room)

@socketio.on('leave')
def on_leave(data):
    if 'user_uuid' not in session:
        return
        
    room = data.get('room')
    if room:
        leave_room(room)

@app.route('/chat/transfer', methods=['POST'])
def chat_transfer():
    if 'user_uuid' not in session:
        return jsonify({'success': False, 'error': '로그인이 필요합니다.'}), 401
        
    data = request.get_json()
    room_uuid = data.get('room_uuid')
    
    if not room_uuid:
        return jsonify({'success': False, 'error': '잘못된 요청입니다.'}), 400
        
    db = get_db()
    cursor = db.cursor()
    
    # 채팅방과 상품 정보 확인
    cursor.execute("""
        SELECT cr.*, p.price, p.is_sold, p.seller_uuid
        FROM chat_room cr
        JOIN product p ON cr.product_uuid = p.uuid
        WHERE cr.uuid = ? AND cr.buyer_uuid = ?
    """, (room_uuid, session['user_uuid']))
    
    room = cursor.fetchone()
    if not room:
        return jsonify({'success': False, 'error': '잘못된 접근입니다.'}), 403
        
    if room['is_sold']:
        return jsonify({'success': False, 'error': '이미 판매된 상품입니다.'}), 400
    
    # 구매자 잔액 확인
    cursor.execute("SELECT balance FROM user WHERE uuid = ?", (session['user_uuid'],))
    buyer = cursor.fetchone()
    
    if buyer['balance'] < room['price']:
        return jsonify({'success': False, 'error': '잔액이 부족합니다.'}), 400
    
    # 거래 처리
    try:
        # 상품 상태 업데이트
        cursor.execute("UPDATE product SET is_sold = 1 WHERE uuid = ?", (room['product_uuid'],))
        
        # 잔액 이동
        cursor.execute("UPDATE user SET balance = balance - ? WHERE uuid = ?", 
                      (room['price'], session['user_uuid']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE uuid = ?", 
                      (room['price'], room['seller_uuid']))
        
        db.commit()
        
        # 거래 완료 메시지 전송
        socketio.emit('message', {
            'sender_uuid': session['user_uuid'],
            'message': f"상품 구매가 완료되었습니다. (거래금액: {room['price']}원)",
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }, room=room_uuid)
        
        return jsonify({'success': True})
        
    except Exception as e:
        db.rollback()
        return jsonify({'success': False, 'error': '거래 처리 중 오류가 발생했습니다.'}), 500

@app.route('/chat/delete/<room_uuid>', methods=['POST'])
@login_required
def delete_chat_room(room_uuid):
    try:
        db = get_db()
        cursor = db.cursor()
        
        # 채팅방 정보 가져오기
        cursor.execute("""
            SELECT * FROM chat_room 
            WHERE uuid = ?
        """, (room_uuid,))
        chat_room = cursor.fetchone()
        
        if not chat_room:
            return jsonify({'error': '채팅방을 찾을 수 없습니다.'}), 404
            
        # 현재 사용자가 채팅방의 참여자인지 확인
        if chat_room['buyer_uuid'] != session['user_uuid'] and chat_room['seller_uuid'] != session['user_uuid']:
            return jsonify({'error': '권한이 없습니다.'}), 403
            
        # 채팅 메시지 삭제
        cursor.execute("DELETE FROM chat_message WHERE chat_room_uuid = ?", (room_uuid,))
        
        # 채팅방 삭제
        cursor.execute("DELETE FROM chat_room WHERE uuid = ?", (room_uuid,))
        
        db.commit()
        return jsonify({'message': '채팅방이 삭제되었습니다.'}), 200
        
    except Exception as e:
        db.rollback()
        print(f"Error deleting chat room: {str(e)}")
        return jsonify({'error': '채팅방 삭제 중 오류가 발생했습니다.'}), 500

@app.route('/payment')
@login_required
def payment():
    if 'user_uuid' not in session:
        return redirect(url_for('login'))
        
    db = get_db()
    cursor = db.cursor()
    
    # 사용자 정보 가져오기
    cursor.execute("SELECT * FROM user WHERE uuid = ?", (session['user_uuid'],))
    user = cursor.fetchone()
    
    if not user:
        flash('사용자 정보를 찾을 수 없습니다.')
        return redirect(url_for('logout'))
    
    # 거래 내역 가져오기 (충전 및 송금 내역)
    cursor.execute("""
        SELECT t.uuid,
               t.sender_uuid,
               t.receiver_uuid,
               t.amount,
               t.type,
               t.balance_after,
               datetime(t.created_at, '+9 hours') as created_at,
               s.id as sender_id,
               r.id as receiver_id
        FROM transactions t
        JOIN user s ON t.sender_uuid = s.uuid
        JOIN user r ON t.receiver_uuid = r.uuid
        WHERE t.sender_uuid = ? OR t.receiver_uuid = ?
        ORDER BY t.created_at DESC
        LIMIT 20
    """, (session['user_uuid'], session['user_uuid']))
    
    transactions = []
    for tx in cursor.fetchall():
        tx_dict = dict(tx)
        # SQLite timestamp 문자열을 datetime 객체로 변환
        tx_dict['created_at'] = datetime.strptime(tx_dict['created_at'], '%Y-%m-%d %H:%M:%S')
        transactions.append(tx_dict)
    
    return render_template('payment.html', user=user, transactions=transactions)

@app.route('/charge', methods=['POST'])
@login_required
def charge_balance():
    amount = request.form.get('amount', type=int)
    
    if not amount or amount not in [10000, 30000, 50000, 100000]:
        flash('올바른 충전 금액을 선택해주세요.')
        return redirect(url_for('payment'))
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        # 현재 잔액 확인
        cursor.execute("SELECT balance FROM user WHERE uuid = ?", (session['user_uuid'],))
        current_balance = cursor.fetchone()['balance']
        new_balance = current_balance + amount
        
        # 거래 기록 생성 (충전)
        transaction_uuid = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO transactions (uuid, sender_uuid, receiver_uuid, amount, type, balance_after)
            VALUES (?, ?, ?, ?, 'CHARGE', ?)
        """, (transaction_uuid, session['user_uuid'], session['user_uuid'], amount, new_balance))
        
        # 잔액 업데이트
        cursor.execute("UPDATE user SET balance = ? WHERE uuid = ?", 
                      (new_balance, session['user_uuid']))
        
        db.commit()
        flash(f'{amount:,}원이 충전되었습니다.')
        
    except Exception as e:
        db.rollback()
        flash('충전 처리 중 오류가 발생했습니다.')
        print(f"Charge error: {str(e)}")
        
    return redirect(url_for('payment'))

def get_chat_room_by_uuid(room_uuid):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            cr.*,
            p.title as product_name,
            p.price as product_price,
            p.uuid as product_uuid,
            u1.id as buyer_id,
            u2.id as seller_id,
            u1.uuid as buyer_uuid,
            u2.uuid as seller_uuid
        FROM chat_room cr
        JOIN product p ON cr.product_uuid = p.uuid
        JOIN user u1 ON cr.buyer_uuid = u1.uuid
        JOIN user u2 ON cr.seller_uuid = u2.uuid
        WHERE cr.uuid = ?
    """, (room_uuid,))
    return cursor.fetchone()

@socketio.on('payment_request')
def handle_payment_request(data):
    if 'user_uuid' not in session:
        emit('payment_error', {'message': '로그인이 필요합니다.'})
        return

    room_uuid = data.get('room_uuid')
    amount = data.get('amount')

    if not room_uuid or not amount:
        emit('payment_error', {'message': '잘못된 요청입니다.'})
        return

    cursor = get_db().cursor()
    
    # 기존 송금 요청 메시지 삭제
    cursor.execute('''
        DELETE FROM chat_message 
        WHERE chat_room_uuid = ? 
        AND message_type = 'payment_request'
    ''', (room_uuid,))

    # 새로운 송금 요청 메시지 저장
    now = datetime.now()
    message_uuid = str(uuid.uuid4())
    cursor.execute('''
        INSERT INTO chat_message (uuid, chat_room_uuid, sender_uuid, content, created_at, message_type, amount)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        message_uuid,
        room_uuid,
        session['user_uuid'],
        f"{amount:,}원의 송금이 요청되었습니다.",
        now,
        'payment_request',
        amount
    ))
    get_db().commit()

    # 송금 요청 이벤트 전송
    emit('payment_request', {
        'amount': amount,
        'type': 'payment_request'
    }, room=room_uuid)

@socketio.on('sale_complete')
def handle_sale_complete(data):
    room_uuid = data.get('room_uuid')
    
    # 채팅방 정보 조회
    chat_room = get_chat_room_by_uuid(room_uuid)
    if not chat_room:
        return
    
    # 판매자만 거래 완료 가능
    if session.get('user_uuid') != chat_room['seller_uuid']:
        return
        
    try:
        cursor = get_db().cursor()
        
        # 판매자의 현재 잔액 조회
        cursor.execute('SELECT balance FROM user WHERE uuid = ?', (chat_room['seller_uuid'],))
        seller = cursor.fetchone()
        
        # 가장 최근 거래 금액 조회
        cursor.execute('''
            SELECT amount FROM transactions 
            WHERE receiver_uuid = ? AND sender_uuid = ?
            ORDER BY created_at DESC LIMIT 1
        ''', (chat_room['seller_uuid'], chat_room['buyer_uuid']))
        
        transaction = cursor.fetchone()
        if not transaction:
            emit('payment_error', {'message': '거래 내역을 찾을 수 없습니다.'}, room=request.sid)
            return
            
        amount = transaction['amount']
        
        # 판매자의 잔액 증가
        cursor.execute('''
            UPDATE user 
            SET balance = balance + ? 
            WHERE uuid = ?
        ''', (amount, chat_room['seller_uuid']))
        
        # 거래 기록 추가
        cursor.execute('''
            INSERT INTO transactions (uuid, sender_uuid, receiver_uuid, amount, type, balance_after)
            VALUES (?, ?, ?, ?, 'complete', ?)
        ''', (
            str(uuid.uuid4()),
            chat_room['seller_uuid'],
            chat_room['seller_uuid'],
            amount,
            seller['balance'] + amount
        ))
        
        get_db().commit()
        emit('sale_complete', room=room_uuid)
        
    except Exception as e:
        get_db().rollback()
        print(f"Error in sale_complete: {e}")
        emit('payment_error', {'message': '거래 완료 처리 중 오류가 발생했습니다.'}, room=request.sid)

@socketio.on('payment_refund')
def handle_payment_refund(data):
    room_uuid = data.get('room_uuid')
    
    # 채팅방 정보 조회
    chat_room = get_chat_room_by_uuid(room_uuid)
    if not chat_room:
        return
    
    # 판매자만 환불 가능
    if session.get('user_uuid') != chat_room['seller_uuid']:
        return
        
    try:
        cursor = get_db().cursor()
        
        # 가장 최근 거래 금액 조회
        cursor.execute('''
            SELECT amount FROM transactions 
            WHERE receiver_uuid = ? AND sender_uuid = ?
            ORDER BY created_at DESC LIMIT 1
        ''', (chat_room['seller_uuid'], chat_room['buyer_uuid']))
        
        transaction = cursor.fetchone()
        if not transaction:
            emit('payment_error', {'message': '거래 내역을 찾을 수 없습니다.'}, room=request.sid)
            return
            
        amount = transaction['amount']
        
        # 구매자의 현재 잔액 조회
        cursor.execute('SELECT balance FROM user WHERE uuid = ?', (chat_room['buyer_uuid'],))
        buyer = cursor.fetchone()
        
        # 구매자에게 환불
        cursor.execute('''
            UPDATE user 
            SET balance = balance + ? 
            WHERE uuid = ?
        ''', (amount, chat_room['buyer_uuid']))
        
        # 거래 기록 추가
        cursor.execute('''
            INSERT INTO transactions (uuid, sender_uuid, receiver_uuid, amount, type, balance_after)
            VALUES (?, ?, ?, ?, 'refund', ?)
        ''', (
            str(uuid.uuid4()),
            chat_room['seller_uuid'],
            chat_room['buyer_uuid'],
            amount,
            buyer['balance'] + amount
        ))
        
        get_db().commit()
        emit('payment_refund', room=room_uuid)
        
    except Exception as e:
        get_db().rollback()
        print(f"Error in payment_refund: {e}")
        emit('payment_error', {'message': '환불 처리 중 오류가 발생했습니다.'}, room=request.sid)

@app.route('/chat/room/<room_uuid>')
@login_required
def chat_room(room_uuid):
    cursor = get_db().cursor()
    cursor.execute('SELECT balance FROM user WHERE uuid = ?', (session['user_uuid'],))
    user = cursor.fetchone()
    if not user:
        flash('사용자 정보를 찾을 수 없습니다.')
        return redirect(url_for('logout'))
    
    balance = user['balance']
    session['balance'] = balance

    # 채팅방 정보 조회
    cursor.execute('''
        SELECT cr.*, p.title as product_name, p.price as product_price,
               s.id as seller_id, s.uuid as seller_uuid,
               b.id as buyer_id, b.uuid as buyer_uuid
        FROM chat_room cr
        JOIN product p ON cr.product_uuid = p.uuid
        JOIN user s ON p.seller_uuid = s.uuid
        LEFT JOIN user b ON cr.buyer_uuid = b.uuid
        WHERE cr.uuid = ?
    ''', (room_uuid,))
    room = cursor.fetchone()

    if not room:
        return redirect(url_for('index'))

    if session['user_uuid'] not in [room['seller_uuid'], room['buyer_uuid']]:
        return redirect(url_for('index'))

    # 채팅 메시지 조회
    cursor.execute('''
        SELECT cm.*, u.id as sender_id
        FROM chat_message cm
        JOIN user u ON cm.sender_uuid = u.uuid
        WHERE cm.chat_room_uuid = ?
        ORDER BY cm.created_at ASC
    ''', (room_uuid,))
    
    messages = []
    for msg in cursor.fetchall():
        message = dict(msg)
        try:
            timestamp = message['created_at']
            if '.' in timestamp:
                message['created_at'] = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
            else:
                message['created_at'] = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        except (ValueError, TypeError):
            message['created_at'] = datetime.now()
        messages.append(message)

    return render_template('chat_room.html', room=room, messages=messages)

@socketio.on('payment_transfer')
def handle_payment_transfer(data):
    if 'user_uuid' not in session:
        emit('payment_error', {'message': '로그인이 필요합니다.'})
        return

    room_uuid = data.get('room_uuid')
    amount = data.get('amount')

    if not room_uuid or not amount:
        emit('payment_error', {'message': '잘못된 요청입니다.'})
        return

    db = get_db()
    cursor = db.cursor()

    try:
        # 채팅방 정보 조회
        cursor.execute("""
            SELECT cr.*, p.seller_uuid
            FROM chat_room cr
            JOIN product p ON cr.product_uuid = p.uuid
            WHERE cr.uuid = ? AND cr.buyer_uuid = ?
        """, (room_uuid, session['user_uuid']))
        
        chat_room = cursor.fetchone()
        if not chat_room:
            emit('payment_error', {'message': '채팅방을 찾을 수 없습니다.'})
            return

        # 구매자 잔액 확인
        cursor.execute("SELECT balance FROM user WHERE uuid = ?", (session['user_uuid'],))
        buyer = cursor.fetchone()
        if buyer['balance'] < amount:
            emit('payment_error', {'message': '잔액이 부족합니다.'})
            return

        # 송금 처리
        cursor.execute("UPDATE user SET balance = balance - ? WHERE uuid = ?", 
                      (amount, session['user_uuid']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE uuid = ?", 
                      (amount, chat_room['seller_uuid']))

        # 거래 기록 생성
        transaction_uuid = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO transactions (uuid, sender_uuid, receiver_uuid, amount, type, balance_after)
            VALUES (?, ?, ?, ?, 'TRANSFER', ?)
        """, (transaction_uuid, session['user_uuid'], chat_room['seller_uuid'], 
              amount, buyer['balance'] - amount))

        # 시스템 메시지 저장
        message_uuid = str(uuid.uuid4())
        now = datetime.now()
        cursor.execute("""
            INSERT INTO chat_message (uuid, chat_room_uuid, sender_uuid, content, message_type, created_at)
            VALUES (?, ?, ?, ?, 'system', ?)
        """, (message_uuid, room_uuid, session['user_uuid'], 
              f"{amount:,}원이 송금되었습니다.", now))

        db.commit()

        # 송금 완료 메시지 전송
        emit('chat_message', {
            'uuid': message_uuid,
            'content': f"{amount:,}원이 송금되었습니다.",
            'type': 'system',
            'created_at': now.strftime('%Y-%m-%d %H:%M:%S')
        }, room=room_uuid)

    except Exception as e:
        db.rollback()
        print(f"Error in payment_transfer: {e}")
        emit('payment_error', {'message': '송금 처리 중 오류가 발생했습니다.'})

if __name__ == '__main__':
    socketio.run(app, debug=True)

