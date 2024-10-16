from flask import Flask, render_template, request, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
import pytz
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yoursecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'static/images'  

#Initialise
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

#Destination model
class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image_filename = db.Column(db.String(150), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('destinations', lazy=True))


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    destination_id = db.Column(db.Integer, db.ForeignKey('destination.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('comments', lazy=True))

#Route for mydestination
@app.route('/explore/<int:destination_id>', methods=['GET', 'POST'])
@login_required
def explore_destination(destination_id):
    destination = Destination.query.get_or_404(destination_id)
    
    if request.method == 'POST':
        content = request.form['comment']
        new_comment = Comment(content=content, destination_id=destination.id, user_id=current_user.id)
        db.session.add(new_comment)
        db.session.commit()
        flash("Comment added!", "success")
        return redirect(url_for('explore_destination', destination_id=destination_id))
    
    comments = Comment.query.filter_by(destination_id=destination_id).order_by(Comment.timestamp.desc()).all()
    return render_template('explore_destination.html', destination=destination, comments=comments)

#load user
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash("Username or email already exists. Please choose another.", "danger")
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for('home'))
        else:
            flash("Login failed. Check your username and password.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/createDestination', methods=['GET', 'POST'])
@login_required
def create_destination():
    if request.method == 'POST':
        name = request.form['destination-name']
        description = request.form['description']
        image = request.files['image']

        if image:
            filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(image_path)
        else:
            filename = None  

        new_destination = Destination(name=name, description=description, image_filename=filename, user_id=current_user.id)
        db.session.add(new_destination)
        db.session.commit()

        flash("Destination created successfully!", "success")
        return redirect(url_for('destinations'))

    return render_template('createDestination.html')

@app.route('/destinations')
def destinations():
    return render_template('destination.html')

@app.route('/explorecity.html')
def explore_city():
    return render_template('explorecity.html')

@app.route('/explore')
def explore():
    return render_template('explore.html')

@app.route('/admin/users')
def viewusers():
    users = User.query.all()
    return render_template('viewusers.html', users=users)

@app.route('/admin/destinations')
def view_destinations():
    destinations = Destination.query.all()
    return render_template('viewdestinations.html', destinations=destinations)

@app.route('/mydestinations')
@login_required
def my_destinations():
    user_destinations = Destination.query.filter_by(user_id=current_user.id).all()
    return render_template('myDestinations.html', destinations=user_destinations)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)
