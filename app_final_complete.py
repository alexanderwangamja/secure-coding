
import sqlite3
import uuid
import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.utils import secure_filename

# ✅ 1. 환경변수 로딩
load_dotenv()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# ✅ 2. Flask 인스턴스 생성
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ✅ 3. SocketIO 설정
socketio = SocketIO(app)

# ✅ 4. 최초 실행 시 admin 계정 자동 생성
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.before_first_request
def create_admin_if_not_exists():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE username = 'admin'")
    if not cursor.fetchone():
        admin_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
            (admin_id, 'admin', ADMIN_PASSWORD)
        )
        db.commit()

# ✅ 5. 파일 확장자 체크 함수
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT,
                is_suspended INTEGER DEFAULT 0,
                balance INTEGER DEFAULT 10000
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                image TEXT,
                is_blocked INTEGER DEFAULT 0,
                seller_id TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL
            )
        """)
        db.commit()


#(2/3)


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone():
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        if user:
            if user['is_suspended']:
                flash('휴면 계정입니다.')
                return redirect(url_for('login'))
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호 오류')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    query = request.args.get('q', '').strip()
    if query:
        cursor.execute("SELECT * FROM product WHERE is_blocked = 0 AND title LIKE ?", ('%' + query + '%',))
    else:
        cursor.execute("SELECT * FROM product WHERE is_blocked = 0")
    products = cursor.fetchall()
    return render_template('dashboard.html', user=user, products=products)

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        bio = request.form['bio']
        current_password = request.form.get('current_password', '').strip()
        new_password = request.form.get('new_password', '').strip()

        # 소개글은 항상 업데이트
        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))

        # 비밀번호 변경 로직
        if current_password and new_password:
            cursor.execute("SELECT password FROM user WHERE id = ?", (session['user_id'],))
            stored_pw = cursor.fetchone()['password']
            if stored_pw == current_password:
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_password, session['user_id']))
                flash("비밀번호가 변경되었습니다.")
            else:
                flash("현재 비밀번호가 올바르지 않습니다.")
        elif new_password:  # 현재 비밀번호 없이 변경 시도
            flash("비밀번호를 변경하려면 현재 비밀번호를 입력해야 합니다.")

        db.commit()
        return redirect(url_for('profile'))

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user)

#(3/3)


@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        image_file = request.files['image']
        image_filename = None
        if image_file and allowed_file(image_file.filename):
            image_filename = secure_filename(str(uuid.uuid4()) + '_' + image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            image_file.save(image_path)
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute("""
            INSERT INTO product (id, title, description, price, image, seller_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (product_id, title, description, price, image_filename, session['user_id']))
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

@app.route('/my-products')
def my_products():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE seller_id = ?", (session['user_id'],))
    products = cursor.fetchall()
    return render_template('my_products.html', products=products)


@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product or product['is_blocked']:
        flash('이 상품은 존재하지 않거나 차단되었습니다.')
        return redirect(url_for('dashboard'))
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

@app.route('/transfer', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    if request.method == 'POST':
        target_id = request.form['target_id'].strip()
        reason = request.form['reason'].strip()

        if not target_id or not reason:
            flash("신고 대상과 사유를 모두 입력해야 합니다.")
            return redirect(url_for('report'))

        report_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()

        # 신고 누적 검사 함수 호출
        check_report_threshold()

        flash("신고가 접수되었습니다.")
        return redirect(url_for('dashboard'))

    return render_template('report.html')
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        target_username = request.form['target']
        amount = int(request.form['amount'])
        cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
        sender = cursor.fetchone()
        cursor.execute("SELECT * FROM user WHERE username = ?", (target_username,))
        receiver = cursor.fetchone()
        if not receiver:
            flash("수신자가 존재하지 않습니다.")
            return redirect(url_for('transfer'))
        if receiver['id'] == sender['id']:
            flash("자기 자신에게는 송금할 수 없습니다.")
            return redirect(url_for('transfer'))
        if sender['balance'] < amount:
            flash("잔액이 부족합니다.")
            return redirect(url_for('transfer'))
        cursor.execute("UPDATE user SET balance = balance - ? WHERE id = ?", (amount, sender['id']))
        cursor.execute("UPDATE user SET balance = balance + ? WHERE id = ?", (amount, receiver['id']))
        db.commit()
        flash(f"{target_username}님께 {amount}원 송금 완료!")
        return redirect(url_for('dashboard'))
    return render_template('transfer.html')


@app.route('/admin/reports')
def view_all_reports():
    if session.get('username') != 'admin':
        flash("접근 권한이 없습니다.")
        return redirect(url_for('dashboard'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT r.id, r.reason, r.reporter_id, r.target_id, u.username as reporter
        FROM report r
        JOIN user u ON r.reporter_id = u.id
    """)
    reports = cursor.fetchall()
    return render_template('report_list.html', reports=reports)

@app.route('/my-reports')
def my_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT id, target_id, reason FROM report
        WHERE reporter_id = ?
    """, (session['user_id'],))
    reports = cursor.fetchall()
    return render_template('my_reports.html', reports=reports)



def check_report_threshold():
    db = get_db()
    cursor = db.cursor()

    # 상품 신고 누적 3회 이상인 상품 → 차단
    cursor.execute("""
        SELECT target_id FROM report
        WHERE target_id IN (SELECT id FROM product)
        GROUP BY target_id
        HAVING COUNT(*) >= 3
    """)
    for row in cursor.fetchall():
        cursor.execute("UPDATE product SET is_blocked = 1 WHERE id = ?", (row['target_id'],))

    # 사용자 신고 누적 5회 이상인 사용자 → 휴면 처리
    cursor.execute("""
        SELECT target_id FROM report
        WHERE target_id IN (SELECT id FROM user)
        GROUP BY target_id
        HAVING COUNT(*) >= 5
    """)
    for row in cursor.fetchall():
        cursor.execute("UPDATE user SET is_suspended = 1 WHERE id = ?", (row['target_id'],))

    db.commit()


if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)

