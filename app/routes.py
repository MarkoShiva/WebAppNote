from app import app, db
from flask import render_template, flash, redirect, url_for, request, g, jsonify
from app.forms import LoginForm, RegistrationForm, ResetPasswordForm, ResetPasswordRequestForm, NotesForm, TasksForm, DocumForm
from flask_login import current_user, login_user, logout_user
from flask_login import current_user, login_required
from app.models import User, Notes, Tasks, Document
from app.email import send_password_reset_email

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password')
            return render_template('errors/404.html', title="wrong credentials"), 404
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for("secret"))
    return render_template('auth/login.html', title='Sign In', form=form)


@app.route('/')
@app.route('/index')
@login_required
def index():
    return render_template('index.html', title='Home')


@app.route("/secret", methods=['GET'])
@login_required
def secret():
    return render_template('secret.html', title='Secret')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data, fullname=form.fullname.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('auth/register.html', title='Register',
                           form=form)


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('login'))
    return render_template('auth/reset_password_request.html',
                           title='Reset Password', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('login'))
    return render_template('auth/reset_password.html', form=form)

"""
    @ToDo will need the at least one main route for each app
    and later maybe add different routes for PUT and DELETE?
    Or add them to the same?
"""


# route will in case of GET request list all and it will have a form underneath that will be used for sending a
# POST request. I do will separate PUT from that route as in teh Vue.js they might be a single form then again I do want
# to handle them separately for now.
@app.route('/notes', methods=['GET', 'POST']) #Todo Will need also PUT and DELETE
def notes():
    # timestamp = datetime.utcnow() - timedelta(days=10) # Todo add some filter on how much notes I want to return
    form = NotesForm()
    if form.validate_on_submit():
        note = Notes(content=form.content.data, title=form.title.data)
        db.session.add(note)
        db.session.commit()
        flash('Your note is now live!')
        return redirect(url_for('notes'))
    notes_list = Notes.query.order_by(Notes.created_at.desc())
    return render_template('notes.html', notes=notes_list, form=form)








@app.route('/tasks', methods=['GET', 'POST'])
def tasks():
    # timestamp = datetime.utcnow() - timedelta(days=10) # Todo add some filter on how much notes I want to return
    form = DocumForm()
    if form.validate_on_submit():
        document = Tasks(description=form.content.data, title=form.title.data)
        db.session.add(document)
        db.session.commit()
        flash('Your document is now saved')
        return redirect(url_for('document'))
    docum_list = Document.query.order_by(Document.created_at.desc())
    return render_template('document.html', documents=docum_list, form=form)


@app.route('/document', methods=['GET', 'POST'])
def document():
    form = TasksForm()
    if form.validate_on_submit():
        task = Tasks(description=form.description.data, title=form.title.data, percentage=form.percentage.data
                     , tags=form.tags.data)
        db.session.add(task)
        db.session.commit()
        flash('Your task is now added')
        return redirect(url_for('tasks'))
    tasks_list = Tasks.query.order_by(Tasks.created_at.desc())
    return render_template('tasks.html', tasks=tasks_list, form=form)
