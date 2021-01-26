from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, DateField, IntegerField
from flask_wtf.file import FileField, FileRequired, FileAllowed
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
from wtforms.validators import DataRequired, Email
import MySQLdb.cursors

app = Flask(__name__)
app.secret_key = 'planetrader'


#config SQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'planetrader'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Init MYSQL
mysql = MySQL(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/aboutus')
def aboutus():
    return render_template('aboutus.html')

@app.route('/contactus')
def contactus():
    return render_template('contactus.html')

@app.route('/products') # <--need to change
def products():
    return render_template('products.html')

@app.route('/shippinginfo')
def shippinginfo():
    return render_template('shippinginfo.html')

@app.route('/paymentmethod')
def paymentmethod():
    return render_template('paymentmethod.html')

@app.route('/privacypolicy')
def privacypolicy():
    return render_template('privacypolicy.html')

@app.route('/returnandrefundpolicy')
def returnandrefundpolicy():
    return render_template('returnandrefundpolicy.html')

@app.route('/details') #details of products
def details():
    return render_template('details.html')


        
class RegisterForm(Form):
    firstname = StringField ('First name', [validators.length(min=1, max=50)])
    lastname = StringField ('Last name', [validators.length(min=1, max=50)])
    email = StringField ('Email', validators=[DataRequired(), Email()])
    phone = StringField ('Phone Number', [validators.length(min=5,max=20)])
    username = StringField ('Username', [validators.length(min=6, max=25)])
    password = PasswordField ('Password',[validators.DataRequired(),validators.
        EqualTo('confirm', message='Password does not match')])
    confirm = PasswordField ('Confirm password')

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        firstname = form.firstname.data
        lastname = form.lastname.data
        email = form.email.data
        phone = form.phone.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        # Check if account exists using MySQL
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM members WHERE username = %s', (username,))
        account = cur.fetchone()
        # If account exists show error and validation checks
        if account:
            flash("Username already exists!", "warning")
        else:
            cur.execute("Insert into members(firstname,lastname,email,phone,username,password) values (%s, %s, %s, %s, %s, %s) ", (firstname, lastname, email, phone, username, password))
            mysql.connection.commit()
            cur.close()
            flash("You are now registered and can login", "success")
            return redirect(url_for('index'))
        
    return render_template('register.html', form = form)

 #Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
           return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', "danger")
            return redirect(url_for('login'))
    return wrap

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method =='POST':
        username = request.form['Username']
        password_candidate = request.form['Password']

        # Create cursor
        cur = mysql.connection.cursor()

        # Get User by username
        result = cur.execute("SELECT * FROM members WHERE username = %s", [username])
        if result >0:
            data = cur.fetchone()
            password = data['password']

            # Compare password
            if sha256_crypt.verify(password_candidate, password):
                session["logged_in"] = True
                session["username"] = username

                flash("You are now logged in", 'success')
                return redirect(url_for('index'))
            else:
                error = "Invalid login"
                return render_template('login.html', error = error)
            cur.close()
        else:
            error = 'Username not found'
            return render_template('login.html', error = error)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You are now logged out','success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@ is_logged_in
def dashboard():
        return render_template('dashboard.html')

@app.route('/profile')
@ is_logged_in
def profile():
    # We need all the account info for the user so we can display it on the profile page
        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM members WHERE username = %s', [session['username']])
        members = cur.fetchone()
        # Show the profile page with account info
        return render_template('profile.html',members=members)

if __name__ == "__main__":
    app.run(port=5000,debug=True)