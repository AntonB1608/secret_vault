from flask import Flask, request, render_template, session, redirect
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import datetime as dt
from dotenv import load_dotenv
import os
from flask_wtf.csrf import CSRFProtect
import secrets 
from flask_mail import Mail, Message


load_dotenv()
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv("GMAIL_USER")
app.config['MAIL_PASSWORD'] = os.getenv("GMAIL_PASSWORD")
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
csrf = CSRFProtect(app)
mail = Mail(app)
db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=True)
    trys = db.Column(db.Integer, default=0)
    email = db.Column(db.String(40), unique = True, nullable = False )
    email_verified = db.Column(db.Boolean, default=False)
    token = db.Column(db.String(32))
    locked_until = db.Column(db.DateTime, nullable=True)




@app.route("/register", methods=["POST", "GET"])
def register():
    
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        if len(username) > 20:
            return render_template("register.html", fehlermeldung="username too long")
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            return render_template("register.html", fehlermeldung = "Username already taken")
        email_exists = User.query.filter_by(email=email).first()
        if email_exists:
            return render_template("register.html", fehlermeldung = "email already taken", username=username)
        else:
            token = secrets.token_urlsafe(32)
            new_user = User(username=username, email=email, token=token, email_verified=False)
            db.session.add(new_user)
            db.session.commit()
            msg = Message(
            subject="Verify your email",
            sender=os.getenv("GMAIL_USER"),
            recipients=[email]
            )
            msg.body = f"Click this link to verify your email: http://localhost:5555/verify/{token}"
            mail.send(msg)
            return render_template("check_email.html")        
    else:
        return render_template("register.html") 
@app.route('/verify/<token>')
def verifiy_user(token):    
    user = User.query.filter_by(token = token).first()
    if not user:
        return "Invalid token"
    user.email_verified = True
    user.token = None
    session["username"] = user.username
    db.session.commit()
    return redirect("/setpassword")

@app.route('/setpassword', methods = ["POST", "GET"] )
def setpassword():
    if request.method == "POST":
        username = session["username"]
        user = User.query.filter_by(username=username).first()  
        if user.email_verified == True and user.token == None:
            sonderzeichen = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
            password = request.form["password"]
            if len(password) < 15:
                return render_template("setpassword.html", fehlermeldung = "password to short", username=username)
            has_sonderzeichen = any(zeichen in password for zeichen in sonderzeichen)
            if not has_sonderzeichen:
                return render_template("setpassword.html", fehlermeldung = "password doesn't contain sonderzeichen", username=username)
            password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
            password_again = request.form["password_again"]
            if password == password_again:
                user.password_hash = password_hash          
                db.session.commit()
                return redirect("/login")
            else:
                return render_template("setpassword.html", fehlermeldung = "passwords dont match", username=username, password=password)
        else: 
            return render_template("register.html", fehlermeldung = "Your email is not verified yet.")
    else:
        return render_template("setpassword.html")





        

@app.route("/login", methods=["POST", "GET"])
def login():
    current_date_time = dt.datetime.today()
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template("login.html", fehlermeldung = "User not found")
        if user.locked_until and current_date_time < user.locked_until:
            return render_template("login.html", fehlermeldung=f"You are blocked until {user.locked_until}")
        if user.locked_until and current_date_time > user.locked_until:
            user.trys = 0
            db.session.commit()
        if bcrypt.checkpw(password.encode("utf-8"), user.password_hash):
            user.locked_until = None
            session["username"] = username
            db.session.commit()
            return redirect("/vault")
        
        user.trys += 1
        if user.trys >= 5: 
            user.locked_until = dt.datetime.today() + dt.timedelta(minutes=15)
            db.session.commit()
            return render_template("login.html", fehlermeldung=f"wrong password, you are blocked until {user.locked_until}", username=username)            
        db.session.commit()
        return render_template("login.html", fehlermeldung="wrong password", username=username)
    else:
        return render_template("login.html")
@app.route("/vault", methods = ["GET"])
def vault():
    if "username" not in session:
        return render_template("login.html")
    else:
        return render_template("vault.html", username=session["username"])
@app.route("/logout", methods = ["GET"])
def logout():      
    session.pop("username", None)
    return redirect("/login")
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5555, debug=True)