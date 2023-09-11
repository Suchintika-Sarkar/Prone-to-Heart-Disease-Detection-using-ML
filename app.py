#app.py
import re
from urllib import request
from flask import Flask, render_template, request, redirect
from datetime import datetime
from distutils.log import debug
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
import joblib

# Load the trained model
knn_model = joblib.load('model.pkl')

# Load the dataset
df = pd.read_csv('heart_disease_dataset.csv')

# Preprocess the dataset
X = df.drop('target', axis=1)
y = df['target']
scaler = StandardScaler()
X = scaler.fit_transform(X)

# Train the KNN model
knn_model = KNeighborsClassifier(n_neighbors=5)
knn_model.fit(X, y)

app = Flask(__name__)
app.app_context().push()
'''app.config['SQLALCHEMY_DATABASE_URI']= "sqlite:///todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False'''

#db= SQLAlchemy(app)

'''class Todo(db.Model):
    sno=db.Column(db.Integer, primary_key=True)
    title=db.Column(db.String(200),nullable=False )
    desc=db.Column(db.String(500), nullable=False)+
    date_created=db.Column(db.DateTime, default=datetime.utcnow)'''

app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
#bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True,nullable=False)
    username = db.Column(db.String(120), unique=True,nullable=False)
    email = db.Column(db.String(50), unique=True,nullable=False)
    password = db.Column(db.String(80),nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
#class HeartPred(FlaskForm):

@app.route('/',methods=['GET','POST'])
def hello_world():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect("index.html")

        return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect("/login")
    return render_template('signup.html', form=form)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    # Get the input values from the form
    age = int(request.form['age'])
    sex = int(request.form['sex'])
    cp = int(request.form['cp'])
    trestbps = int(request.form['trestbps'])
    chol = int(request.form['chol'])
    fbs = int(request.form['fbs'])
    restecg = int(request.form['restecg'])
    thalach = int(request.form['thalach'])
    exang = int(request.form['exang'])
    oldpeak = float(request.form['oldpeak'])
    slope = int(request.form['slope'])
    ca = int(request.form['ca'])
    thal = int(request.form['thal'])
    target = int(request.form['target'])

    # Create the input features DataFrame
    features = pd.DataFrame({
        'age': [age],
        'sex': [sex],
        'cp': [cp],
        'trestbps': [trestbps],
        'chol': [chol],
        'fbs': [fbs],
        'restecg': [restecg],
        'thalach': [thalach],
        'exang': [exang],
        'oldpeak': [oldpeak],
        'slope': [slope],
        'ca': [ca],
        'thal': [thal],
        'target': [target]
    })

    # Make the prediction
    prediction = knn_model.predict(features)[0]

    if prediction == 1:
        result = 'Heart Disease detected.'
    else:
        result = 'Heart Disease not detected.'

    return render_template('guest.html', prediction=result)

@app.route('/guest', methods=['GET', 'POST'])
def guest_login():
    # Logic for guest login
    return render_template('guest.html')

if __name__ == '__main__':
    app.run(debug=True)