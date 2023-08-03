import json
import os
import re
from datetime import timedelta
from functools import wraps
from typing import List, Dict, Any

import postgrest
from dotenv import load_dotenv
from flask import Flask, render_template, jsonify, url_for, redirect, session, request, flash, send_file
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from supabase import Client, create_client
from supabase.client import SupabaseException
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import ValidationError, InputRequired, Length

load_dotenv()
key = os.getenv('KEY')
url = os.getenv('URL')

supabase: Client = create_client(url, key)
ALLOW_PATH = ['/', '/login', '/register', '/admin', '/fetch-app', '/add', '/logout', '/favicon.ico', '/fetch-admin']
ALLOW_LOCK = ['/admin', '/login', '/lock']
ADMIN_LIST = ['מנהל ראשי']

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
csrf = CSRFProtect(app)
app.permanent_session_lifetime = timedelta(days=20)

LOCK = False
SEND = True


# -------------------- start function ------------------------------------- #
def admin_required(view_func):
    """
    Decorator function to enforce that only users with administrative privileges can access specific views.

    :param view_func: The original view function to be wrapped.
    :return: The wrapped view function.
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_name_check = session.get('user_name')
        if session.get('allow_user') and user_name_check in ADMIN_LIST:
            return view_func(*args, **kwargs)
        else:
            flash('נא להתחבר כמנהל כדי לגשת לדף זה.', 'error')
            return redirect(url_for('log_out'))

    return wrapped_view


def login_required(view_func):
    """
    Decorator function to enforce that only authenticated users can access specific views.

    :param view_func: The original view function to be wrapped.
    :return: The wrapped view function.
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        user_name_check = session.get('user_name')
        if session.get('allow_user') and user_name_check:
            return view_func(*args, **kwargs)
        else:
            flash('נא להתחבר כדי לגשת לדף זה.', 'error')
            return redirect(url_for('login'))

    return wrapped_view


def unlock(view_func):
    """
    Decorator function to control access to views when the website is in a locked state.

    :param view_func: The original view function to be wrapped.
    :return: The wrapped view function.
    """

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        if LOCK:
            return view_func(*args, **kwargs)
        else:
            flash('נא להתחבר כדי לגשת לדף זה.', 'error')
            return redirect(url_for('/'))

    return wrapped_view


def fetch_post() -> List[Dict[str, Any]]:
    """
    Fetches all the messages from the "message" table in the database.

    :return: A list of dictionaries representing the messages, each containing "message" and "user_pub" keys.
    """
    response = supabase.from_("message").select("message, user_pub").execute().json()
    messages = json.loads(response)
    return messages.get('data')


def admin_lock() -> bool:
    """
    Locks the website by updating the "admin-panel" table in the database.

    :return: True if the website is successfully locked; otherwise, False.
    """
    global LOCK, SEND
    try:
        update_data = {'lock': True, 'send': False}
        supabase.from_('admin-panel').update(update_data).eq('id', '1').execute()
        LOCK, SEND = True, False
        return True
    except SupabaseException:
        return False


def admin_unlock() -> bool:
    """
    Unlocks the website by updating the "admin-panel" table in the database.

    :return: True if the website is successfully unlocked; otherwise, False.
    """
    global LOCK, SEND
    try:
        update_data = {'lock': False, 'send': True}
        supabase.from_('admin-panel').update(update_data).eq('id', '1').execute()
        LOCK, SEND = False, True
        return True
    except SupabaseException:
        return False


def user_exists(username: str) -> bool:
    """
    Checks if a user with the given username exists in the "users" table of the database.

    :param username: The username to check.
    :return: True if the user exists; otherwise, False.
    """
    try:
        response = supabase.from_("users").select("username").eq("username", username).limit(1).execute().json()
        user_data_list = json.loads(response).get('data')
        return bool(user_data_list)
    except postgrest.exceptions.APIError:
        return False


def new_user(username: str, password: str) -> bool:
    """
    Creates a new user in the "users" table of the database.

    :param username: The username for the new user.
    :param password: The password for the new user.
    :return: True if the user is successfully created; otherwise, False.
    """
    try:
        check = user_exists(username)
        if check:
            return False
        supabase.from_('users').insert({'username': username, 'password': password}).execute()
        return True
    except postgrest.exceptions.APIError as e:
        if 'users_username_key' in e.message:
            return False
    return False


def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticates a user by checking if the provided username and password match a user in the database.

    :param username: The username to authenticate.
    :param password: The password to authenticate.
    :return: True if the user is authenticated and has administrative privileges (admin=True); otherwise, False.
    """
    try:
        response = supabase.from_("users").select("username", "password", "admin").eq("username", username).limit(
            1).execute().json()
        user_data_list = json.loads(response).get('data')
        if not user_data_list:
            return False
        user_data = user_data_list[0]
        hashed_password = user_data.get('password')
        result = check_password_hash(hashed_password, password)
        admin = bool(user_data.get('admin'))
        return result and admin
    except (postgrest.exceptions.APIError, ValueError, TypeError, IndexError):
        return False


def send_post(post: str, user: str) -> bool:
    """
    Sends a new post to the database with the name of the user who sent the message.

    :param post: The text of the message to post.
    :param user: The username of the user sending the message.
    :return: True if the message is successfully sent; otherwise, False.
    """
    try:
        res = supabase.from_('message').insert({'message': post, 'user_pub': user}).execute()
        return tuple(res)[0][1]
    except Exception:
        return False


def fetch_admin() -> json:
    """
    Fetches all the messages from the "message" table in the database for the admin-panel.

    :return: A list of dictionaries representing the messages, each containing "id" "message" and "user_pub" keys.
    """
    res = supabase.from_('message').select('id', 'message', 'user_pub').execute()
    return res.json()


def delete_by_id(message_id: str) -> bool:
    """
    Deletes a message from the "message" table in the database based on its ID.

    :param message_id: The ID of the message to delete.
    :return: True if the message is successfully deleted; otherwise, False.
    """
    try:
        res = supabase.from_('message').delete().eq('id', message_id).execute()
        return tuple(res)[0][1]
    except Exception:
        return False


def allow_cher(_, field):
    """
    Custom validator function for the form class to check if the field data contains special characters.

    :param _: The FlaskForm instance (not used in the function).
    :param field: The field to validate.
    :raises ValidationError: If special characters
    (e.g., '@', '#', '^', '[', ']', '{', '}', '|', '<', '>') are found in the field data.
    """
    if re.search(r'[@#^\[\]{}|<>]', field.data):
        raise ValidationError('Special characters are not allowed.')


def valid_name(name: str) -> bool:
    """
    Checks if a given name is valid based on the specified pattern.
    The name is considered valid if it contains only letters
    (both uppercase and lowercase) and has a length between 4 and 12 characters.

    :param name: name (str): The name to be validated.
    :return: bool: True if the name is valid; otherwise, False.
    """
    pattern = r'^[a-zA-Z]{4,12}$'
    return bool(re.match(pattern, name))


# ------------------------- start class -------------------------------#
class AddMessage(FlaskForm):
    message = StringField('message', validators=[InputRequired(),
                                                 allow_cher,
                                                 Length(max=100, message='max 100 letter allow')])


class Login(FlaskForm):
    password = PasswordField('password', validators=[InputRequired()])
    username = StringField('username', validators=[InputRequired()])


class Register(FlaskForm):
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=100)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=12)])


class AdminForm(FlaskForm):
    lock_web = BooleanField('Lock Website')
    delete = StringField('messgae-id')
    submit = SubmitField('Save')


# ----------------- start route -------------------------------------#
@app.before_request
def check_path():
    """
    Before each request, this function is called to check the path and control access based on the LOCK status.

    If the website is locked (LOCK is True), it checks if the requested path is allowed for locked users (ALLOW_LOCK).
    If the path is allowed for locked users, the request continues as usual; otherwise,
    it redirects to the 'lock' route.

    If the website isn't locked (LOCK is False), it checks if the requested path allowed for all users (ALLOW_PATH).
    If the path is allowed for all users, the request continues as usual; otherwise,
    it redirects to the root path ('/').

    :return:
    """
    if LOCK:
        if request.path in ALLOW_LOCK:
            return
        else:
            return redirect(url_for('lock'))
    if request.path not in ALLOW_PATH:
        return redirect('/')
    return


@app.after_request
def remove_server_header(response):
    response.headers['Server'] = ''
    return response


@app.errorhandler(400)
def csrf_token_missing_error(error):
    if 'CSRF token missing' in str(error):
        flash('csrf is miss', 'error'), 400
        return jsonify({'error': 'נתקלנו בשגיאה נסה לטעון את הדף מחדש'}), 400
    else:
        flash('bad request', 'error'), 400
        return jsonify({'error': 'בקשה שגויה טען את הדף מחדש'}), 400


@app.route('/', methods=['GET'])
@login_required
def index():
    form = AddMessage()
    return render_template('index.html', form=form)


@app.route('/add', methods=['POST'])
@login_required
def add_message():
    form = AddMessage()
    if form.validate_on_submit():
        try:
            if not SEND:
                flash('שליחת הודעה חסומה כרגע')
                return jsonify({'send': 'False'}), 200

            message = form.message.data
            name = session.get('user_name')
            send_post(message, name)

            flash('ההודעה נשלחה בהצלחה.', 'success')
            return jsonify({'send': 'True'}), 200

        except SupabaseException:
            flash('שליחת ההודעה נכשלה. בבקשה נסה שוב מאוחר יותר.', 'error')
            return jsonify({'error': 'הודעה לא נשלחה נסה שוב.'}), 500

    flash('קרתה שגיאה נא לשלוח הודעה ללא תווים מיוחדים.', 'error')
    return jsonify({'error': 'קרתה שגיאה נסה שוב מאוחר יותר.'}), 500


@app.route('/fetch-app')
@login_required
def fetch_all():
    return jsonify({'message': fetch_post()})


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if authenticate_user(username, password):
            session.update({
                'user_name': username,
                'allow_user': True
            })
            return jsonify({'login': 'success'})
        else:
            return jsonify({'error': 'שם משתמש או סיסמה לא חוקיים, או שהחשבון אינו אושר על ידי הבעלים. בבקשה נסה '
                                     'שוב מאוחר יותר'})

    return render_template('login.html', form=form)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = Register()
    if request.method == 'POST' and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        new = new_user(username, generate_password_hash(password))
        if new:
            return jsonify({'success': 'נרשמתה בהצלחה! בקשת הרשמה נשלחה למנהל נא לנסות להתחבר במועד מאוחר יותר'})
        else:
            return jsonify({'error': 'משתמש קיים או שהחשבון לא אושר על ידי המנהל נסה שוב מאוחר יותר'})

    return render_template('register.html', form=form)


@app.route('/logout', methods=['GET'])
@login_required
def log_out():
    session.clear()
    return redirect(url_for('login'))


@app.route('/lock')
@unlock
def lock():
    return render_template('lock.html')


@app.route('/fetch-admin', methods=['GET'])
@admin_required
def admin_messages():
    return fetch_admin()


@app.route('/admin', methods=['GET', 'POST'])
@admin_required
def admin_panel():
    form = AdminForm()

    if request.method == 'POST' and form.validate_on_submit():
        locked = form.lock_web.data
        delete = form.delete.data
        if delete:
            delete_by_id(delete)
        if locked:
            admin_lock()
            return jsonify({"success": "Website locked successfully!"})
        else:
            admin_unlock()
            return jsonify({"success": "Website unlocked successfully!"})

    return render_template('admin.html', form=form)


@app.route('/favicon.ico')
def favicon():
    return send_file('templates/chat.png', mimetype='image/png')


# ----------------- end route -------------------------------------#

if __name__ == '__main__':
    app.run(debug=False)
