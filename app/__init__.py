from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap

from flask_login import LoginManager
from flask_mail import Mail
from flask_mail_sendgrid import MailSendGrid
from config import Config
from flask import Flask
from flask_moment import Moment

app = Flask(__name__)
app.config.from_object(Config)
# app.config['EXPLAIN_TEMPLATE_LOADING'] = True
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)
login.login_view = 'login'
login.login_message = 'Please log in to access this page.'
bootstrap = Bootstrap(app)
mail = MailSendGrid(app)
moment = Moment(app)

from app import models, routes, handlers
