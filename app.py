#All these libraries need to be installed on the system using the package manager, PIP on CMD. 
from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
from random import randint
from time import strftime
from flask import Flask, render_template, flash, request
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
#This is imported from the data.py in the same folder where firstpro.py exists.
#from data import Articles
#MYSQL packages that operate with MySQL Database
from flask_mysqldb import MySQL, MySQLdb
#wtforms are built in forms that need to be installed on our system using pip and fileds need to included
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
#passlib.hash is used for encrypting our password we want to use. 
from passlib.hash import sha256_crypt
import mysql.connector
from functools import wraps
import os
from werkzeug.utils import secure_filename
from keras.preprocessing.image import img_to_array
from tensorflow.keras.models import load_model
import numpy as np
import argparse
import scipy
import scipy.misc as ii
import imutils
import cv2
#The name of the core python file always assigned built in Flask constructor 
firstpro = Flask(__name__)

#config MySQL
firstpro.config['MYSQL_HOST'] = 'localhost'
firstpro.config['MYSQL_USER'] = 'root'
firstpro.config['MYSQL_PASSWORD'] = ''
firstpro.config['MYSQL_DB'] = 'myflaskapp'
firstpro.config['MYSQL_CURSORCLASS'] = 'DictCursor'
UPLOAD_FOLDER = 'UploadedFiles'
firstpro.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#initialization of mysql
mysql = MySQL(firstpro)


ALLOWED_EXTENSIONS = set(['jpeg','jpg','png'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@firstpro.route('/home')
def name():
    return render_template("index.html")


#A class for registration form 
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password',[
        validators.DataRequired(),
        validators.EqualTo('confirm', message="Password do not match")
    ])
    confirm = PasswordField('Confirm Password')

#Registration form will be appeared here. 
@firstpro.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        #Create cursor

        cur = mysql.connection.cursor()
        #mycursor = mydb.cursor(buffered=True)

        cur.execute("INSERT  INTO nusers(name, email, username, password) VALUES (%s,%s,%s,%s)", (name, email, username, password))
        #mycursor.execute("INSERT INTO `nusers`(`name`, `email`, `username`, `password`) VALUES(%s, %s,%s,%s)", (name, email, username,password))
            
        #commit
        mysql.connection.commit()

        cur.close()
        #mycursor.close()
        flash('You are registered', 'success')

        redirect(url_for('login'))

    return render_template('register.html', form=form)

@firstpro.route('/login', methods =['GET', 'POST'])
def login():
    if request.method == 'POST':
#get form fields
        username = request.form['username']
        password_candidate = request.form['password']

    #create a cursor

        cur = mysql.connection.cursor()

    #get user by user name 
        result = cur.execute("SELECT * FROM nusers WHERE username = %s", [username])

        if result > 0:
        #get started 
            data = cur.fetchone()
            password = data['password']

        #compare passwords 

            if sha256_crypt.verify(password_candidate, password):

                #sessions
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('inde'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
            cur.close()

        else:
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')

#Decorators: check for flask decorators and choose flsk snippet

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):

        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized', 'danger')
            return redirect(url_for('login'))
    return wrap


#Login Page 
@firstpro.route('/logout')
def logout():
    session.clear()
    flash('You are logged out', 'success')
    return render_template('login.html')


class ReusableForm(Form):
    name = TextField('Name:', validators=[validators.required()])
    surname = TextField('Surname:', validators=[validators.required()])

def get_time():
    time = strftime("%Y-%m-%dT%H:%M")
    return time

def write_to_disk(name, surname, email):
    data = open('file.log', 'a')
    timestamp = get_time()
    data.write('DateStamp={}, Name={}, Surname={}, Email={} \n'.format(timestamp, name, surname, email))
    data.close()

@firstpro.route("/upload")
@is_logged_in
def inde():
    return render_template("uploadd.html")

@firstpro.route("/uploads" , methods=['POST'])
def upload():
    form = ReusableForm(request.form)
    name=request.form['name']
    surname=request.form['surname']
    email=request.form['email']
    file = request.files['file']
    if form.validate():
        write_to_disk(name, surname, email)
        flash('Hello: {} {}'.format(name, surname))
    else:
        flash('Error: All Fields are Required')

    
    filename = secure_filename(file.filename)
    file.save(os.path.join(firstpro.config['UPLOAD_FOLDER'], filename))

    image = ii.imread(file)
    orig = image.copy()
    image=cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    image = cv2.resize(image, (224, 224))

    image = image.astype("float") / 255.0
    image = img_to_array(image)
    image = np.expand_dims(image, axis=0)
    model = load_model('covid19.model')
    (notSanta, santa) = model.predict(image)[0]
    label = "NORMAL" if santa > notSanta else "COVID19 INFECTED"
    proba = santa if santa > notSanta else notSanta
    label = "{}: {:.2f}%".format(label, proba * 100)
    output = imutils.resize(orig, width=400)
    cv2.putText(output, label, (10, 25),  cv2.FONT_HERSHEY_SIMPLEX,0.7, (0, 255, 0), 2)
    print(label)

    return render_template("complete.html",variable=label)



#This exists in every core python file. If this is true, the system is commanded to proceed and run the page. 
if __name__ == "__main__":
#The debug should be kept True all the time; it helps us when we refresh the page, we will not lose our data. and 
#we dont need to restart the server again. 
    firstpro.secret_key='keyhenw' #Secret key for the purpose of security
    firstpro.run(debug=True)
