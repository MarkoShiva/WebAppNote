from _datetime import datetime

from app import db, login

from time import time
from flask import current_app, url_for
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import jwt



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(128))
    username = db.Column(db.String(32), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    email = db.Column(db.String(160), index=True, unique=True)
    token = db.Column(db.String(32), index=True, unique=True)
    token_expiration = db.Column(db.DateTime)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            current_app.config['SECRET_KEY'],
            algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, current_app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)



@login.user_loader
def load_user(id):
    return User.query.get(int(id))


class Notes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String())
    title = db.Column(db.String(64), index=True)
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, index=True, default=datetime.utcnow) # Todo need to implement update of the notes field.
    language = db.Column(db.String(5))


class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String())
    title = db.Column(db.String(64), index=True)
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    percentage = db.Column(db.Integer)
    tags = db.Column(db.String(180))
    language = db.Column(db.String(5))


# Need Work implement notification system I have example in Website project.
# Do I need it?

# Todo add document model
# Todo one more

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String())
    title = db.Column(db.String(64), index=True)
    created_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    modified_at = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    description = db.Column(db.Integer)
    language = db.Column(db.String(5))
