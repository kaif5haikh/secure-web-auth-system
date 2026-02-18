from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime



db = SQLAlchemy()

class User(db.Model,UserMixin):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(100),unique=True,nullable=False)
  email = db.Column(db.String(150),unique=True,nullable=False)
  password=db.Column(db.String(200),nullable=False)
  role=db.Column(db.String(20),default="user")

  # Adding this new coloum for preventing brute-fore attack
  failed_attempts = db.Column(db.Integer,default=0)
  is_locked = db.Column(db.Boolean,default=False)
  
  #Setting lock time
  lock_time = db.Column(db.DateTime,nullable=True)

  def __repr__(self):
    return f"<User{self.username}>" 