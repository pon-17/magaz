from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField, FloatField, FileField
from wtforms.fields.simple import EmailField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Optional


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
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