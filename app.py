from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nutz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    password_history = db.relationship('PasswordHistory', backref='user', lazy=True)

class PasswordHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    is_public = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route('/')
def index():
    if 'user_id' in session:
        public_posts = Post.query.filter_by(is_public=True).order_by(Post.created_at.desc()).all()
        user_posts = Post.query.filter_by(user_id=session['user_id']).order_by(Post.created_at.desc()).all()
        return render_template('home.html', public_posts=public_posts, user_posts=user_posts)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter((User.username == username)|(User.email == email)).first():
            flash('Username or Email already exists')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        db.session.add(PasswordHistory(user_id=user.id, password_hash=password_hash))
        db.session.commit()
        flash('Registered successfully!')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login successful!')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!')
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current = request.form['current_password']
        new = request.form['new_password']
        user = User.query.get(session['user_id'])

        if not check_password_hash(user.password_hash, current):
            flash('Current password is incorrect')
            return redirect(url_for('change_password'))

        history = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.created_at.desc()).limit(3).all()
        for entry in history:
            if check_password_hash(entry.password_hash, new):
                flash('New password cannot be same as last 3 passwords')
                return redirect(url_for('change_password'))

        new_hash = generate_password_hash(new)
        user.password_hash = new_hash
        db.session.add(PasswordHistory(user_id=user.id, password_hash=new_hash))
        db.session.commit()
        flash('Password changed successfully')
        return redirect(url_for('index'))

    return render_template('change_password.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/my_posts')
def my_posts():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    posts = Post.query.filter_by(user_id=session['user_id']).order_by(Post.created_at.desc()).all()
    return render_template('my_posts.html', posts=posts)

@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != session.get('user_id'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        post.content = request.form['content']
        post.is_public = request.form.get('is_public') == 'on'
        db.session.commit()
        flash('Post updated!')
        return redirect(url_for('my_posts'))

    return render_template('edit_post.html', post=post)

@app.route('/delete_post/<int:post_id>')
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id == session.get('user_id'):
        db.session.delete(post)
        db.session.commit()
        flash('Post deleted.')
    return redirect(url_for('my_posts'))

@app.route('/post', methods=['GET', 'POST'])
def post():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        content = request.form['content']
        is_public = request.form.get('is_public') == 'on'
        new_post = Post(content=content, is_public=is_public, user_id=session['user_id'])
        db.session.add(new_post)
        db.session.commit()
        flash('Post created!')
        return redirect(url_for('index'))

    return render_template('post.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(debug=True)
