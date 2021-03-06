import os
from sqlalchemy.dialects import registry


class Config(object):
    basedir = os.path.abspath(os.path.dirname(__file__))
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dont-know-passphrase'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMINS = ['admin@testapp.com']
    SENDGRID_DEFAULT_FROM = 'admin@testapp.com'
    MAIL_SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
