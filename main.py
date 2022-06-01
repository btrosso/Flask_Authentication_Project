import os

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

login_manager = LoginManager()
login_manager.init_app(app)

app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

#Line below only required once, when creating DB. 
# db.create_all()

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@login_manager.user_loader
def load_user(user_id):
    """
    When you log in, Flask-Login creates a cookie that contains your User.id.
    This is just an id, a string, not the User object itself; at this point, it
    doesn't know your name or email etc. When you go to a new page that tries to
    access the current_user and its properties, as when we print the user's name
    on the secrets page, Flask-Login needs to create a User object from the stored
    user_id to do so. It does by calling the user_loader decorated function. So, even
    though we don't explicitly call that function, in fact we've used it on every page.
    """
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        if User.query.filter_by(email=request.form.get('email')).first():
            flash('This email has already been registered. Would you like to log in?')
            return redirect(url_for('login'))
        else:
            hash_and_salted_password = generate_password_hash(
                request.form.get('password'),
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=request.form.get('email'),
                name=request.form.get('username'),
                password=hash_and_salted_password.split("$")[2]
            )
            db.session.add(new_user)
            db.session.commit()

            #Log in and authenticate user after adding details to database.
            login_user(new_user)
            #render_template("secrets.html", name=new_user.name)
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        #Find user by email entered.
        user = User.query.filter_by(email=email).first()
        if user is not None:
            #Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('secrets'))
            else:
                flash('Incorrect Password. Try again.')
                return redirect(url_for('login'))
        else:
            flash('Sorry, but that email has not been registered yet.')
            return redirect(url_for('login'))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory=os.environ['UPLOAD_PATH'], filename='cheat_sheet.pdf')

@app.route('/delete/<id>', methods=['GET', 'POST'])
def delete_user(id):
    user_to_delete = User.query.get(id)
    db.session.delete(user_to_delete)
    db.session.commit()
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
