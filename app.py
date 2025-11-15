from flask import Flask, render_template, request, redirect, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import hashlib
import secrets
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///InnerFlow.db'
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class DiaryEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'date': self.date.isoformat(),
            'content': self.content,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


def hash_password(password):
    salt = secrets.token_hex(16)
    return hashlib.sha256((password + salt).encode()).hexdigest() + ':' + salt


def verify_password(password, stored_hash):
    try:
        stored_hash, salt = stored_hash.split(':')
        return stored_hash == hashlib.sha256((password + salt).encode()).hexdigest()
    except:
        return False


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function


@app.route("/")
def landing():
    return render_template('landing.html')

@app.route("/registration")
def registration():
    return render_template('registration.html')

@app.route("/login")
def login_page():
    return render_template('login.html')


@app.route("/main")
@login_required
def main():
    return render_template('main.html')

@app.route("/diary")
@login_required
def diary():
    selected_date = request.args.get('date')
    return render_template('diary.html', selected_date=selected_date)

@app.route("/harmony")
@login_required
def harmony():
    return render_template('harmony.html')

@app.route("/forum")
@login_required
def forum():
    return render_template('forum.html')

@app.route("/psychologists")
@login_required
def psychologists():
    return render_template('psychologists.html')


@app.route("/quick-register", methods=['POST'])
def quick_register():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or len(username) < 3:
            return jsonify({'success': False, 'error': 'Ник должен быть не менее 3 символов'})

        if not password or len(password) < 6:
            return jsonify({'success': False, 'error': 'Пароль должен быть не менее 6 символов'})

        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Этот ник уже занят'})

        password_hash = hash_password(password)
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id
        session['username'] = username
        session['created_at'] = new_user.created_at.isoformat()

        return jsonify({
            'success': True,
            'message': 'Аккаунт успешно создан!',
            'redirect_to': '/'
        })

    except Exception as e:
        return jsonify({'success': False, 'error': 'Ошибка сервера: ' + str(e)})


@app.route("/quick-login", methods=['POST'])
def quick_login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Введите ник и пароль'})

        user = User.query.filter_by(username=username).first()

        if user and verify_password(password, user.password_hash):
            session['user_id'] = user.id
            session['username'] = username
            session['created_at'] = user.created_at.isoformat()

            return jsonify({
                'success': True,
                'message': 'Вход выполнен успешно!',
                'redirect_to': '/'
            })
        else:
            return jsonify({'success': False, 'error': 'Неверный ник или пароль'})

    except Exception as e:
        return jsonify({'success': False, 'error': 'Ошибка сервера: ' + str(e)})

@app.route("/logout")
def logout():
    session.clear()
    return redirect('/')


@app.route('/save-diary-entry', methods=['POST'])
def save_diary_entry():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Необходимо авторизоваться'})

    data = request.get_json()
    content = data.get('content')
    date_str = data.get('date')

    if not content:
        return jsonify({'success': False, 'error': 'Запись не может быть пустой'})

    try:
        # Парсим дату из строки
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Проверяем, есть ли уже запись на эту дату
        existing_entry = DiaryEntry.query.filter_by(
            user_id=session['user_id'],
            date=date
        ).first()

        if existing_entry:
            # Обновляем существующую запись
            existing_entry.content = content
            existing_entry.updated_at = datetime.utcnow()
            message = 'Запись обновлена'
        else:
            # Создаем новую запись
            new_entry = DiaryEntry(
                user_id=session['user_id'],
                date=date,
                content=content
            )
            db.session.add(new_entry)
            message = 'Запись сохранена'

        db.session.commit()
        return jsonify({'success': True, 'message': message})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': f'Ошибка сохранения: {str(e)}'})


@app.route('/get-diary-entry', methods=['GET'])
def get_diary_entry():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Необходимо авторизоваться'})

    date_str = request.args.get('date')

    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()

        entry = DiaryEntry.query.filter_by(
            user_id=session['user_id'],
            date=date
        ).first()

        if entry:
            return jsonify({'success': True, 'entry': entry.to_dict()})
        else:
            return jsonify({'success': True, 'entry': None})

    except Exception as e:
        return jsonify({'success': False, 'error': f'Ошибка загрузки: {str(e)}'})


@app.route('/get-diary-entries', methods=['GET'])
def get_diary_entries():
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Необходимо авторизоваться'})

    # Получаем все записи пользователя
    entries = DiaryEntry.query.filter_by(user_id=session['user_id']).order_by(DiaryEntry.date.desc()).all()

    return jsonify({
        'success': True,
        'entries': [entry.to_dict() for entry in entries]
    })


def init_db():
    with app.app_context():
        db.create_all()
        print("✅ База данных инициализирована!")


if __name__ == '__main__':
    init_db()
    app.run(debug=True)