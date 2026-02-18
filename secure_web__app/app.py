from flask_login import LoginManager,login_user,login_required,logout_user,current_user,UserMixin
from flask import Flask,render_template,redirect,request
from flask_wtf import CSRFProtect

from models import db,User
from flask_bcrypt import Bcrypt
import os
import re # import this for add input validation
from datetime import datetime,timedelta,timezone

#import this for adding decorator for checking admin role this is used for Advanded RBAC.
from functools import wraps
from flask import redirect,url_for

# UX handling
from flask import flash

#importing session module
from flask import session
from flask import abort #import this for using in admin required funtion 

# importing these two modules for adding IP rate limiting login
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


  

app = Flask(__name__)

limiter = Limiter(
  get_remote_address,
  app=app,
  default_limits=["200 per day","50 per hour"]
  #Only 5 login attempts per minute per IP.
  #After that → 429 Too Many Requests.

)
bcrypt = Bcrypt(app)

csrf  = CSRFProtect(app)



app.config['SECRET_KEY'] = 'supersecretkey'
# This is used for:
# Session security
# CSRF protection
# Signing cookies
# Without SECRET_KEY:
# Login sessions won’t work properly
# Flask-WTF won’t work
# In real production:
# Never hardcode secret keys.

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

#Adding Session Security / cookie security
app.config["SESSION_COOKIE_HTTPONLY"] = False # This cookie cannot be accessed using JavaScript and Flask sets HttpOnly=True by default.
app.config["SESSION_COOKIE_SECURE"] = False # tRue only if https off in development but live after deployment
app.config["PERMANENT_SESSION_LIFETIME"] = 1800 # 30 MINUTE --> User must login again.



#managing login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view  = "login"

db.init_app(app)

@app.route("/")
def home():
  return render_template("home.html")

# Regsiter route
@app.route("/register",methods=["GET","POST"])
def Register():
  if request.method == "POST":
    
    username=request.form.get("Username")
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
      return "username already exists"
    email=request.form.get("email")

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return "Email already registered "
    
    password=request.form.get("password")

    if len(password) < 8 :
      return "Password must be at least 8 characters"
    
    if not re.search(r"[A-Z]",password):
      return 'Passowrd must contain at least one uppercase letter'
    
    if not re.search(r"[0-9]",password):
      return 'Password must contain at least one number'

    hashed_password=bcrypt.generate_password_hash(password).decode('utf-8') # hashing password


    new_user = User(
      username=username,
      email=email,
      password=hashed_password
    )
    db.session.add(new_user)
    db.session.commit()

    return "User Registered Successfully!"
  return render_template("register.html")


#Add user loader
@login_manager.user_loader
def load_user(user_id):
  return User.query.get(int(user_id)) # This tells Flask-Login how to load user from DB.


#creating login route
@app.route("/login",methods=["GET","POST"])
@limiter.limit("5 per minute")
def login():
  if request.method == "POST":
    email = request.form.get("email")
    passwrod = request.form.get("password")

    user = User.query.filter_by(email=email).first()
      # this is = (SELECT * FROM user WHERE email = 'entered_email' LIMIT 1);
      # If user exists → returns user object
      #  If not → returns None
    
    # This means:Does user exist?
    if not user:
      flash("Invalid Credentials","danger")
      return redirect(url_for("login"))
    
    #checking if account is locked
    if user.is_locked:

      # Adding unlocked minute check feature
      if user.lock_time and datetime.utcnow() > user.lock_time + timedelta(minutes=15):
        user.is_locked = False
        user.failed_attempts = 0
        user.lock_time = None
        db.session.commit()
      else:
        flash("Account is locked for 15 minutes due to multiple failed attempts.","Warning")
        return redirect(url_for("login"))

    #check password
    if bcrypt.check_password_hash(user.password,passwrod):
      """
      Does password match?
      If yes → login success
      If no → invalid credentials
      """
      user.failed_attempts = 0 # setting 0 to failed_attempt coloum to reset after login
      db.session.commit()

      login_user(user)
      flash("Login Successful","success")
      return redirect(url_for("dashboard"))
    else:
      user.failed_attempts += 1
      print(user.failed_attempts)

      # Account Lock feature
      if user.failed_attempts >=5:
        user.is_locked = True # locked account after 5 failed attempt
        user.lock_time = datetime.utcnow() # adding locked time after account is locked due to 5 consecutive entering incorrect password
        print(user.lock_time)
      
      db.session.commit()

      flash("Invalid Credentials","danger")
      return redirect(url_for("login"))
    
  return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
  """
  Now dashboard is protected.
  If not logged in → redirect to login.
  """
  return render_template("dashboard.html")


@app.route("/logout",methods=["POST"])
@login_required
def logout():
  logout_user()
  session.clear() #remove all session data
  flash("You have been logged out succesfully","success")

  return redirect(url_for("login"))


# instead of checcking role i can do this using custom decorator
def admin_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
    # Must be logged in first:
    if not current_user.is_authenticated:
      return redirect(url_for("login"))
    
    #must be admin
    if current_user.role != "admin":
      # return "Access Denied"
      abort(403)
    
    return f(*args, **kwargs)
  return decorated_function

# Creating my own decorator for checkign admin login
@app.route("/admin")
@admin_required
def admin():
  """
  🧠 What Is Happening Here?
  1️⃣ @login_required → Must be logged in
  2️⃣ Check:
  current_user.role
  3️⃣ If not admin → block
  4️⃣ If admin → allow
  This is Authorization.
  Role-Based Access Control (RBAC)
  This is used in:
  Banking systems
  Admin panels
  Enterprise apps
  """
  # if current_user.role != "admin":
  #   return "Access Denied"
  # return "Welcome Admin "

  return render_template("admin.html")
    
@app.errorhandler(403)
def forbidden(e):
  return render_template("403.html"),403

@app.errorhandler(404)
def not_found(e):
  return render_template("404.html"),404

@app.errorhandler(429)
def ratelimit_handler(e):
  return render_template("429.html"),429

if __name__ == "__main__":
  with app.app_context():
    db.create_all() #creates database automatically
  app.run(debug=True)