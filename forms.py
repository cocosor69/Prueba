from flask import Flask, render_template, request, redirect, session
from models import db, User
from flask_bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret_key_test'
db.init_app(app)

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user'] = user.name
            session['role'] = user.role
            return redirect('/dashboard')
        else:
            return "Credenciales incorrectas"
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    
    if session['role'] == 'admin':
        return f"Bienvenido ADMIN {session['user']}"
    return f"Bienvenido Usuario {session['user']}"

if __name__ == '__main__':
    app.run(debug=True)
