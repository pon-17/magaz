from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'asdadqwdsxcv32434gfergsdf'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html')

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        password_confirm = request.form['password_confirm']

        if password != password_confirm:
            flash('Пароли не совпадают!')
            return redirect(url_for('registration'))

        existing_user = User.query.filter((User .username == username) | (User .email == email)).first()
        if existing_user:
            flash('Пользователь с таким именем или email уже существует!')
            return redirect(url_for('registration'))

        new_user = User(username=username, email=email, password=password)  # Сохраняем пароль в открытом виде
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация прошла успешно! Вы можете войти.')
        return redirect(url_for('login'))

    return render_template('registration.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and user.password == password:  # Проверка пароля в открытом виде
            login_user(user)  # Вход пользователя
            flash('Вы успешно вошли в систему!')  # Сообщение об успешном входе
            return redirect(url_for('profile', username=user.username))  # Перенаправление на страницу профиля
        else:
            flash('Неправильный email или пароль!')  # Сообщение об ошибке

    return render_template('login.html')  # Возврат к форме входа

@app.route('/profile/<username>')
@login_required
def profile(username):  # Убедитесь, что username здесь
    if current_user.username != username:
        flash('У вас нет доступа к этой странице.')
        return redirect(url_for('profile', username=current_user.username))

    return render_template('profile.html', user=current_user)




@app.route('/new_product/')
def new_product():
    return render_template('new_product.html')




if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
