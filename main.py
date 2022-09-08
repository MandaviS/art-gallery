from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from functools import wraps
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL



app = Flask(__name__)
Bootstrap(app)

app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")

class LoginForm(FlaskForm):

    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key = True)
    email = db.Column(db.String(250), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
# db.create_all()

class Painting(db.Model):
    __tablename__ = "Paintings"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    url = db.Column(db.String(250), nullable=False)
# db.create_all()

class AddPaintingForm(FlaskForm):
    Name = StringField("Painting Title", validators=[DataRequired()])
    URL = StringField("URL of image", validators=[DataRequired(), URL()])
    submit = SubmitField("Add Painting")



def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function



@app.route('/')
def home():
    return render_template('index.html', logged_in=current_user.is_authenticated, current_user=current_user)

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method= 'pbkdf2:sha256',
            salt_length= 8,

        )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('home', name=new_user.name))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated, current_user=current_user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", logged_in=current_user.is_authenticated, form=form, current_user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/works')
def works():
    paintings = Painting.query.all()
    return render_template('works.html', all_paintings = paintings)

@app.route("/add", methods=["GET", "POST"])
@admin_only
def add():
    form = AddPaintingForm()

    if form.validate_on_submit():
        new_painting = Painting(
            name=form.Name.data,
            url=form.URL.data,
        )
        db.session.add(new_painting)
        db.session.commit()


        return redirect("works")

    return render_template("add.html", form=form)

@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    painting_to_delete = Painting.query.get(post_id)
    db.session.delete(painting_to_delete)
    db.session.commit()
    return redirect(url_for('works'))

if __name__ == '__main__':
    app.run(debug=True)