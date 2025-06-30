from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256

# --- Flaskアプリケーションの初期化 ---
app = Flask(__name__)

app.secret_key = b'abcdefghijklmn'
# --- データベース設定 ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:hokuto841@localhost:5432/my_app_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# SQLAlchemyの初期化
db = SQLAlchemy(app)

# --- データベースモデルの定義 ---
class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

# --- ルーティングとビュー関数 ---
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    user = User.query.filter_by(username=username).first()

    if user and pbkdf2_sha256.verify(password, user.password):
        # セッションにユーザー情報を保存
        session['user_id'] = user.id
        session['username'] = user.username
        return render_template('result.html', message=f"ようこそ、{username}さん！")
    else:
        flash("ログイン失敗。\nユーザー名またはパスワードを確認してください。")
        return redirect(url_for('home'))

@app.route('/logout')
def logout():
    # セッションからユーザー情報を削除
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('home'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template('result.html', message="ユーザー名はすでに存在します。別のユーザー名を選んでください。")

        hashed_password = pbkdf2_sha256.hash(raw_password)

        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return render_template('result.html', message="登録に成功しました！これでログインできます。")

    return render_template('register.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run(debug=True)
