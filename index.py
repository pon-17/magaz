from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, FloatField, FileField
from wtforms.fields.simple import EmailField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional,Regexp
import random, base64


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'asdadq3242423wdsxcv32434gfer254g6986984352sdf'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[
        DataRequired(),
        Length(min=6, message="Пароль должен быть не менее 6 символов."),
        Regexp('^[A-Za-z0-9]+$', message='Пароль должен содержать только латинские буквы и цифры.')
    ])
    password_confirm = PasswordField('Подтверждение пароля', validators=[DataRequired(), EqualTo('password', message='Пароли должны совпадать')])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

class NewProductForm(FlaskForm):
    name = StringField('Название товара', validators=[DataRequired()])
    price = FloatField('Цена', validators=[DataRequired()])
    condition = SelectField('Состояние товара', choices=[('new', 'Новый'), ('used', 'Б/у')], validators=[DataRequired()])
    category = SelectField('Категория товара', validators=[DataRequired()])
    description = TextAreaField('Описание товара', validators=[Optional()])
    address = StringField('Ваш адрес', validators=[DataRequired()])
    phone_number = StringField('Номер телефона', validators=[DataRequired()])
    photo = FileField('Добавьте фото товара', validators=[DataRequired()])
    submit = SubmitField('Разместить')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    changed = db.Column(db.Boolean, nullable=False, default=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    block = db.Column(db.Boolean, nullable=False, default=False)

class Goods(db.Model):
    __tablename__ = 'goods'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    condition = db.Column(db.String(10), nullable=False)
    category_id =  db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    description = db.Column(db.Text, nullable=True)
    city_id = db.Column(db.Integer, db.ForeignKey('cities.id'), nullable=True)
    address = db.Column(db.String(200), nullable=True)
    phone_number = db.Column(db.String(15), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('goods', lazy=True))
    category = db.relationship('Category', backref=db.backref('goods', lazy=True))
    city = db.relationship('Cities', backref=db.backref('cities', lazy=True))

    def is_favorited_by_user(self, user_id):
        return Favorite.query.filter_by(user_id=user_id, goods_id=self.id).first() is not None

class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    categ_name = db.Column(db.String(100), nullable=False, unique=True)

class Image(db.Model):
    __tablename__ = 'images'
    id = db.Column(db.Integer, primary_key=True)  # Primary key for the images table
    goods_id = db.Column(db.Integer, db.ForeignKey('goods.id'), nullable=False)  # Foreign key to Goods
    image_data = db.Column(db.LargeBinary, nullable=False)  # Store image in binary format

    goods = db.relationship('Goods', backref=db.backref('images', lazy=True))


class Cities(db.Model):
    __tablename__ = 'cities'
    id = db.Column(db.Integer, primary_key=True)
    city = db.Column(db.String(100), nullable=False, unique=True)


class Favorite(db.Model):
    __tablename__ = 'favorites'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    goods_id = db.Column(db.Integer, db.ForeignKey('goods.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('favorites', lazy=True))
    goods = db.relationship('Goods', backref=db.backref('favorites', lazy=True))


@app.template_filter('b64encode')
def b64encode_filter(data):
    if isinstance(data, bytes):
        return base64.b64encode(data).decode('utf-8')
    return ''

def get_categories():
    categories = Category.query.all()
    return categories

def get_cities():
    cities = Cities.query.all()
    return cities

def get_products_by_category(category_name):
    category = Category.query.filter_by(categ_name=category_name).first()
    if not category:
        return []
    products = Goods.query.filter_by(category_id=category.id, is_deleted=False).all()
    return products

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET'])
@app.route('/home', methods=['GET'])
def index():
    categories = get_categories()
    all_goods = Goods.query.filter_by(is_deleted=False).all()
    random_goods = random.sample(all_goods, len(all_goods)) if all_goods else []
    return render_template('index.html', goods=random_goods, categories=categories)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        existing_user = User.query.filter( (User.email == email)).first()
        if existing_user:
            if existing_user.block:
                flash('Пользователь с таким email заблокирован и не может зарегистрироваться.', 'error')
                return render_template('registration.html', form=form)
            else:
                flash('Пользователь с таким email уже существует!', 'error')
                return render_template('registration.html', form=form)

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация прошла успешно! Вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('registration.html', form=form)


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         email = form.email.data
#         password = form.password.data
#         user = User.query.filter_by(email=email).first()
#
#         if user and check_password_hash(user.password, password):
#             login_user(user)
#             return redirect(url_for('profile', username=user.username))
#         else:
#             flash('Неправильный email или пароль!')
#
#     return render_template('login.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            if user.block:
                flash('Ваш аккаунт заблокирован. Обратитесь к администратору.', 'error')
                return redirect(url_for('login'))
            if check_password_hash(user.password, password):
                login_user(user)
                flash('Вы успешно вошли в систему!')
                return redirect(url_for('profile', username=user.username))
        flash('Неправильный email или пароль!')
    return render_template('login.html', form=form)


@app.route('/profile/<username>')
@login_required
def profile(username):
    if current_user.username != username:
        return redirect(url_for('profile', username=current_user.username))

    return render_template('profile.html', user=current_user)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/new_product/', methods=['GET', 'POST'])
@login_required
def new_product():
    cities = get_cities()
    if request.method == 'POST':
        # Получение данных из формы
        name = request.form.get('name')
        price = request.form.get('price')
        condition = request.form.get('condition')
        category_name = request.form.get('category')
        description = request.form.get('description')
        city = request.form.get('city')
        address = request.form.get('address')  # исправлено на 'address'
        phone_number = request.form.get('phone_number')

        # Получаем объект категории по имени
        category = Category.query.filter_by(categ_name=category_name).first()
        city = Cities.query.filter_by(city=city).first()

        # Создаем новый товар
        new_good = Goods(
            name=name,
            price=float(price),
            condition=condition,
            category_id=category.id if category else None,
            description=description,
            city_id=city.id if city else None,
            address=address,
            phone_number=phone_number,
            user_id=current_user.id
        )

        db.session.add(new_good)

        # Обработка изображений
        if 'photo' in request.files:
            photos = request.files.getlist('photo')
            for photo in photos:
                if photo and photo.filename:
                    filename = secure_filename(photo.filename)
                    image_data = photo.read()
                    new_image = Image(goods=new_good, image_data=image_data)
                    db.session.add(new_image)

        db.session.commit()

        return redirect(url_for('profile', username=current_user.username))

    categories = get_categories()

    return render_template('new_product.html', categories=categories, cities=cities)


@app.route('/good_info/<int:good_id>')
def good_detail(good_id):
    good = Goods.query.get_or_404(good_id)
    images = Image.query.filter_by(goods_id=good.id).all()
    good.is_favorited = good.is_favorited_by_user(current_user.id) if current_user.is_authenticated else False
    return render_template('good_info.html', good=good, images=images)


@app.route('/add_to_favorites/<int:good_id>', methods=['POST'])
@login_required
def add_to_favorites(good_id):
    good = Goods.query.get_or_404(good_id)
    existing_favorite = Favorite.query.filter_by(user_id=current_user.id, goods_id=good.id).first()

    if existing_favorite:
        # If the item is already in favorites, remove it
        db.session.delete(existing_favorite)
    else:
        # If the item is not in favorites, add it
        new_favorite = Favorite(user_id=current_user.id, goods_id=good.id)
        db.session.add(new_favorite)

    db.session.commit()
    return redirect(request.referrer)

@app.route('/remove_from_favorites/<int:good_id>', methods=['POST'])
@login_required
def remove_from_favorites(good_id):
    favorite = Favorite.query.filter_by(user_id=current_user.id, goods_id=good_id).first()
    if favorite:
        db.session.delete(favorite)
        db.session.commit()

    return redirect(request.referrer or url_for('favourites'))


@app.route('/owner/<int:user_id>')
def owner(user_id):
    user = User.query.get_or_404(user_id)
    goods = Goods.query.filter_by(user_id=user.id, is_deleted=False).all()
    return render_template('owner.html', user=user, goods=goods)


# @app.route('/search', methods=['GET'])
# def search_products():как
#     search_query = request.args.get('search_bar', '').strip()
#     if search_query:
#         results = Goods.query.filter(func.lower(Goods.name).contains(search_query.lower()), Goods.is_deleted == False).all()
#     else:
#         results = []
#
#     categories = get_categories()
#     return render_template('search.html', goods=results, query=search_query, categories=categories)


@app.route('/search', methods=['GET'])
def search_products():
    search_query = request.args.get('search_bar', '').strip()

    goods = []
    if search_query:
        goods = Goods.query.filter(
            Goods.name.ilike(f'%{search_query}%'),
            Goods.is_deleted == False
        ).all()

    categories = get_categories()
    return render_template('search.html', goods=goods, search_query=search_query, categories=categories)


@app.route('/products/<category_name>')
def products_view(category_name):
    session['current_category'] = category_name
    goods = get_products_by_category(category_name)
    categories = get_categories()
    return render_template('products.html', category_name=category_name, goods=goods, categories=categories)


@app.route('/filters')
def filters():


    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    city = request.args.get('city')
    condition = request.args.get('condition')

    current_category = session.get('current_category')

    if current_category:
        category = Category.query.filter_by(categ_name=current_category).first()
        query = Goods.query.filter_by(category_id=category.id, is_deleted=False)
    else:
        query = Goods.query.filter_by(is_deleted=False)

    if min_price is not None:
        query = query.filter(Goods.price >= min_price)
    if max_price is not None:
        query = query.filter(Goods.price <= max_price)
    if city:
        city_obj = Cities.query.filter_by(city=city).first()
        if city_obj:
            query = query.filter(Goods.city_id == city_obj.id)
    if condition:
        query = query.filter(Goods.condition == condition)

    goods = query.all()

    # Для формы
    # cities = Cities.query.all()
    # categories = Category.query.all()
    cities = Cities.query.all()
    categories = get_categories()
    print(cities)
    return render_template('products.html',
                           goods=goods,
                           categories=categories,
                           cities=cities,
                           current_category=current_category, selected_city=city)


@app.route('/favourites')
@login_required
def favourites():

    favorites = Favorite.query.filter_by(user_id=current_user.id).all()
    goods_list = [favorite.goods for favorite in favorites]

    return render_template('favourites.html', goods=goods_list)


@app.route('/profile/my_ads')
@login_required
def my_ads():
    goods_list = Goods.query.filter_by(user_id=current_user.id, is_deleted=False).all()
    return render_template('my_ads.html', goods=goods_list)


@app.route('/delete_good/<int:good_id>', methods=['POST'])
@login_required
def delete_good(good_id):
    good = Goods.query.filter_by(id=good_id, user_id=current_user.id).first()

    if good:
        good.is_deleted = True
        db.session.commit()

    return redirect(url_for('my_ads'))


@app.route('/edit_product/<int:good_id>', methods=['GET', 'POST'])
@login_required
def edit_product(good_id):
    good = Goods.query.get_or_404(good_id)

    # Проверяем, что текущий пользователь — владелец объявления
    if good.user_id != current_user.id:
        flash('У вас нет прав редактировать это объявление.', 'error')
        return redirect(url_for('profile', username=current_user.username))

    categories = get_categories()
    cities = get_cities()

    if request.method == 'POST':
        # Получаем данные из формы
        name = request.form.get('name')
        price = request.form.get('price')
        condition = request.form.get('condition')
        category_name = request.form.get('category')
        description = request.form.get('description')
        city_name = request.form.get('city')
        address = request.form.get('address')
        phone_number = request.form.get('phone_number')

        # Обновляем поля объявления
        good.name = name
        good.price = float(price) if price else good.price
        good.condition = condition
        category = Category.query.filter_by(categ_name=category_name).first()
        good.category_id = category.id if category else None
        city = Cities.query.filter_by(city=city_name).first()
        good.city_id = city.id if city else None
        good.description = description
        good.address = address
        good.phone_number = phone_number

        # Обработка новых фото (если загружены)
        if 'photo' in request.files:
            photos = request.files.getlist('photo')
            for photo in photos:
                if photo and photo.filename:
                    filename = secure_filename(photo.filename)
                    image_data = photo.read()
                    new_image = Image(goods=good, image_data=image_data)
                    db.session.add(new_image)

        db.session.commit()
        flash('Объявление успешно обновлено!', 'success')
        return redirect(url_for('good_detail', good_id=good.id))

    # GET запрос — отображаем форму с текущими данными
    return render_template('edit_product.html', good=good, categories=categories, cities=cities)


@app.route('/profile/settings/<username>')
@login_required
def settings(username):
    user = User.query.filter_by(username=username).first_or_404()

    return render_template('settings.html', user=user)


@app.route('/profile/settings/update_username', methods=['GET', 'POST'])
@login_required
def update_username():
    user = User.query.filter_by(id=current_user.id).first()

    if request.method == 'POST':
        new_username = request.form.get('username')

        if user:
            user.username = new_username
            db.session.commit()
            return redirect(url_for('settings', username=current_user.username))

    return render_template('update_username.html', user=user)


@app.route('/profile/settings/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    user = User.query.filter_by(id=current_user.id).first()

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')

        if user and check_password_hash(user.password, old_password):
            user.password = generate_password_hash(new_password)
            db.session.commit()
            return redirect(url_for('settings', username=user.username))
        else:
            flash('Неправильный старый пароль.', 'error')

    return render_template('update_password.html', user=user)


@app.route('/admin')
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)  # Доступ запрещён, если не админ
    users = User.query.all()
    goods = Goods.query.filter_by(is_deleted=False).all()
    del_goods = Goods.query.filter_by(is_deleted=True).all()

    return render_template('admin_dash.html', users=users, goods=goods, del_goods=del_goods)


@app.route('/admin/toggle_admin/<int:user_id>', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Вы не можете менять свои права администратора.', 'error')
        return redirect(url_for('admin_panel'))
    user.is_admin = not user.is_admin
    db.session.commit()
    # flash(f'Права администратора у пользователя {user.username} изменены.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin/toggle_block/<int:user_id>', methods=['POST'])
@login_required
def toggle_block(user_id):
    if not current_user.is_admin:
        abort(403)
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Вы не можете блокировать самого себя.', 'error')
        return redirect(url_for('admin_panel'))
    user.block = not user.block
    db.session.commit()
    # flash(f'Пользователь {user.username} {"заблокирован" if user.block else "разблокирован"}.', 'success')
    return redirect(url_for('admin_panel'))


@app.route('/admin_delete_good/<int:good_id>', methods=['POST'])
@login_required
def admin_delete_good(good_id):
    good = Goods.query.filter_by(id=good_id).first()

    if good:
        good.is_deleted = True
        db.session.commit()

    return redirect(url_for('admin_panel'))


@app.route('/admin_recover_good/<int:good_id>', methods=['POST'])
@login_required
def admin_recover_good(good_id):
    good = Goods.query.filter_by(id=good_id).first()

    if good:
        good.is_deleted = False
        db.session.commit()

    return redirect(url_for('admin_panel'))







if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
