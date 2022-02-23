# from crypt import methods
from flask import Blueprint, render_template, request, flash, redirect, url_for
from . import db
# from flask_sqlalchemy import SQLAlchemy
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

# db = SQLAlchemy()


auth = Blueprint("auth", __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    # data = request.form
    # print(data)

    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user, remember=False)
                flash('Logged in successfully!', category='success')
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again!', category="error")
        else:
            flash('Email does not exist!', category='error')

    return render_template("login.html", user=current_user)


@auth.route('/logout')
@login_required
def logout():
    logout_user()

    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def Sign_up():
    if request.method == "POST":
        fname = request.form.get('fname')
        lname = request.form.get('lname')
        email = request.form.get('email')
        password = request.form.get('password')
        passwordconfirm = request.form.get('passwordconfirm')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', category='error')

        elif len(fname) < 2:
            flash('First name must have more than 1 character!', category='error')
            
        elif len(lname) < 2:
            flash('Last name must have more than 1 character!', category='error')
            
        elif len(email) < 4:
            flash('Email address name must have more than 3 character!', category='error')
            
        elif len(password) < 7:
            flash('Password name must have more than 6 character!', category='error')
            
        elif password != passwordconfirm:
            flash('The passwords does not match!', category='error')
            
        else:
            # add user to db
            new_user = User(first_name=fname, last_name=lname, email=email, password=generate_password_hash(password, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(user, remember=True)

            flash('User account successfully created!', category='success')

            return redirect(url_for('views.home'))
            

    return render_template("signup.html", user=current_user)
