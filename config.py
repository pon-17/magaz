from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'asdadq3242423wdsxcv32434gfer254g6986984352sdf'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'