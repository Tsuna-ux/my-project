from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256 # パスワードのハッシュ化・検証用

# --- Flaskアプリケーションの初期化 ---
app = Flask(__name__)

# --- データベース設定 ---
# PostgreSQLの接続URI
# 形式: 'postgresql://ユーザー名:パスワード@ホスト名:ポート番号/データベース名'
# 環境に合わせて以下の値を変更してください
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:hokuto841@localhost:5432/my_app_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # シグナル発行を無効化（メモリを節約するため）

# SQLAlchemyの初期化
db = SQLAlchemy(app)

# --- データベースモデルの定義 ---
# 'users' テーブルに対応するPythonクラス
class User(db.Model):
    __tablename__ = 'users' # データベースのテーブル名と一致させる

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False) # ハッシュ化されたパスワードを保存するため長め

    def __repr__(self):
        return f'<User {self.username}>'

# --- データベースの初期化とテーブル作成（初めて実行するときだけ必要） ---
# この関数は、アプリ起動時にデータベースとテーブルが存在しない場合に作成するために使います。
# 開発中は便利ですが、本番環境ではマイグレーションツール（Alembicなど）を使うのが一般的です。
@app.before_first_request
def create_tables():
    db.create_all()

# --- ルーティングとビュー関数 ---

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # データベースからユーザーを検索
    user = User.query.filter_by(username=username).first()

    if user:
        # パスワードの検証（ハッシュ化されたパスワードと比較）
        if pbkdf2_sha256.verify(password, user.password):
            # flash("ログイン成功！", "success") # メッセージを一時的に保存する場合
            return render_template('result.html', message=f"ようこそ、{username}さん！")
        else:
            # flash("パスワードが間違っています。", "danger")
            return render_template('result.html', message="ログイン失敗。パスワードを確認してください。")
    else:
        # flash("ユーザー名が見つかりません。", "danger")
        return render_template('result.html', message="ログイン失敗。ユーザー名が見つかりません。")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        raw_password = request.form['password']

        # ユーザーが既に存在しないかチェック
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            # flash("ユーザー名はすでに存在します。別のユーザー名を選んでください。", "warning")
            return render_template('result.html', message="ユーザー名はすでに存在します。別のユーザー名を選んでください。")

        # パスワードのハッシュ化
        hashed_password = pbkdf2_sha256.hash(raw_password)

        # 新しいユーザーオブジェクトを作成
        new_user = User(username=username, password=hashed_password)

        # データベースに追加
        db.session.add(new_user)
        db.session.commit() # 変更をコミットしてデータベースに保存

        # flash("登録に成功しました！これでログインできます。", "success")
        return render_template('result.html', message="登録に成功しました！これでログインできます。")

    return render_template('register.html')

if __name__ == '__main__':
    # 開発中にメッセージを表示するための secret_key（flashメッセージを使う場合）
    # app.secret_key = 'your_secret_key_here'
    app.run(debug=True)