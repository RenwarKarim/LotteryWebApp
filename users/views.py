# IMPORTS
import logging
from functools import wraps

from datetime import datetime
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from flask_login import current_user

from app import db, requires_roles
from models import User
from users.forms import RegisterForm, LoginForm
import pyotp

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        pin_key=form.pin_key.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Log the ip address of the user's client and the email of the user if they register along with a message to
        # state they've registered
        logging.warning('SECURITY - User registration [%s, %s]', form.email.data, request.remote_addr)

        # sends user to login page
        return redirect(url_for('users.login'))

    # if request method is GET or form not valid re-render signup page
    return render_template('register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # if session attribute logins does not exist create attribute logins
    if not session.get('logins'):
        session['logins'] = 0
    # if login attempts is 3 or more: create an error message
    elif session.get('logins') >= 3:
        flash('Number of incorrect logins exceeded')

    form = LoginForm()

    if form.validate_on_submit():

        # increase login attempts by 1
        session['logins'] += 1

        # As email addresses are unique, we can search if a submitted email matches to a user account in database
        user = User.query.filter_by(email=form.email.data).first()

        # If we do find a match then we can compare submitted password with actual stored password to see if they match
        if not user or not check_password_hash(user.password, form.password.data):

            # We log the ip address of the user's client since they've made an invalid login attempt, along with a
            # message to state that an invalid login attempt has been made
            logging.warning('SECURITY - Invalid login attempt [%s]', request.remote_addr)

            # if no match create appropriate error message based on login attempts
            if session['logins'] == 3:
                flash('Number of incorrect logins exceeded')
            elif session['logins'] == 2:
                flash('Please check your login details and try again. 1 login attempt remaining')
            else:
                flash('Please check your login details and try again. 2 login attempts remaining')

            return render_template('login.html', form=form)

        # check to see if entered pin is the correct pin that matches user
        if pyotp.TOTP(user.pin_key).verify(form.pin.data):

            # if user is verified reset login attempts to 0
            session['logins'] = 0

            # If passwords match then login the user
            login_user(user)

            # Log the current time that the user has just logged in at and store in database
            user.last_logged_in = user.current_logged_in
            user.current_logged_in = datetime.now()
            db.session.add(user)
            db.session.commit()

            # Log the id, the ip address of user's client and the email of the user if they login along with a
            # message to state they logged in
            logging.warning('SECURITY - Log in [%s, %s, %s]', current_user.id, current_user.email,
                            request.remote_addr)

            # direct to role appropriate page
            if current_user.role == 'admin':
                return redirect(url_for('admin.admin'))
            else:
                return redirect(url_for('users.profile'))

        else:
            flash("You have supplied an invalid 2FA token!", "danger")

    return render_template('login.html', form=form)


@users_blueprint.route('/logout')
@login_required
def logout():
    # Log the id, the ip address of user's client and the email of the user if they logout along with a message to
    # state they logged out
    logging.warning('SECURITY - Log out [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)

    logout_user()
    return redirect(url_for('index'))


# view user profile
@users_blueprint.route('/profile')
@login_required
@requires_roles('user')
def profile():
    return render_template('profile.html', name=current_user.firstname)


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)
