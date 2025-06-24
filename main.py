from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
import random
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Секретный ключ для сессий

# Конфигурация для Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Ваш email
app.config['MAIL_PASSWORD'] = 'your_password'  # Ваш пароль

# Конфигурация базы данных
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # Используем SQLite
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)


# Создание базы данных
with app.app_context():
    db.create_all()

mail = Mail(app)


def generate_verification_code():
    """Генерация уникального кода подтверждения."""
    return ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=5))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')

        # Проверка, существует ли пользователь в базе данных
        user = User.query.filter_by(email=email).first()
        if user is None:
            # Если пользователь не существует, создаем нового
            new_user = User(email=email)
            db.session.add(new_user)
            db.session.commit()

        # Генерация кода подтверждения
        verification_code = generate_verification_code()
        session['verification_code'] = verification_code
        session['email'] = email

        # Отправка кода на почту
        msg = Message('Ваш код подтверждения', sender='your_email@gmail.com', recipients=[email])
        msg.body = f'Ваш код подтверждения: {verification_code}'
        mail.send(msg)

        return redirect(url_for('verify'))

    return render_template('login.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        entered_code = request.form.get('code')

        if entered_code == session.get('verification_code'):
            return redirect(url_for('profile'))
        else:
            flash('Неверный код. Пожалуйста, попробуйте снова или запросите новый код.')

    return render_template('verify.html')


@app.route('/profile')
def profile():
    return "Добро пожаловать в ваш профиль!"


if __name__ == '__main__':
    app.run(debug=True)
