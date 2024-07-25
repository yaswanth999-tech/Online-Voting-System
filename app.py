from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)

# MongoDB connection
client = MongoClient('mongodb://localhost:27017/')
db = client['voting_system']
users = db['users']
votes = db['votes']

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        user_exists = users.find_one({'email': email})
        if user_exists:
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        users.insert_one({'username': username, 'email': email, 'password': hashed_password})
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users.find_one({'email': email})
        
        if user and bcrypt.check_password_hash(user['password'], password):
            session['user'] = user['email']
            
            # Fetch username from the database
            username = user.get('username')
            
            # Check if the user has already voted
            vote_exists = votes.find_one({'user': session['user']})
            if vote_exists:
                flash('You have already voted!', 'danger')
                return redirect(url_for('results'))
            else:
                return redirect(url_for('vote'))
        else:
            flash('Invalid login credentials', 'danger')
    
    return render_template('login.html')
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = users.find_one({'email': email})
        
        if user:
            session['reset_email'] = email
            return redirect(url_for('reset_password'))
        else:
            flash('Email not found', 'danger')
    
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_email' not in session:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password == confirm_password:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            users.update_one({'email': session['reset_email']}, {'$set': {'password': hashed_password}})
            session.pop('reset_email', None)
            flash('Password reset successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Passwords do not match', 'danger')
    
    return render_template('reset_password.html')

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'user' not in session:
        flash('Please log in to vote', 'danger')
        return redirect(url_for('login'))

    # Get the username associated with the email from the users collection
    user = users.find_one({'email': session['user']})
    username = user.get('username') if user else None

    # Check if the user has already voted
    vote_exists = votes.find_one({'user': session['user']})
    if vote_exists:
        flash('You have already voted!', 'danger')
        return redirect(url_for('results'))
    
    if request.method == 'POST':
        candidate = request.form['candidate']
        
        votes.insert_one({'user': session['user'], 'username': username, 'candidate': candidate})
        flash('Vote cast successfully!', 'success')
        return redirect(url_for('results'))
    
    return render_template('vote.html')

@app.route('/results')
def results():
    results = votes.aggregate([
        {'$group': {'_id': '$candidate', 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}}
    ])
    
    return render_template('results.html', results=results)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
