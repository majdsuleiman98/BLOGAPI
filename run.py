from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config["SECRET_KEY"]="a997d5efb248bb348fa26b4e55ee8c01e16d154cfa36de10591b18e449d8f70f"
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+mysqlconnector://root:''@localhost/blog'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db = SQLAlchemy(app)



class User(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    fname=db.Column(db.String(25),nullable=False)
    lname=db.Column(db.String(25),nullable=False)
    username = db.Column(db.String(125),unique=True,nullable=False)
    email=db.Column(db.String(125),unique=True,nullable=False)
    password= db.Column(db.String(60),nullable=False)
    is_admin =db.Column(db.Boolean(),nullable=False, default=False)
    profile_image=db.Column(db.String(20),nullable=False,default="user.png")
    created_at=db.Column(db.DateTime,nullable=False,default=datetime.utcnow)
    blogs = db.relationship("Blog",backref="author",lazy=True)

class Category(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(100),nullable=False)
    description=db.Column(db.Text,nullable=False)
    created_at=db.Column(db.DateTime,nullable=False,default=datetime.utcnow)
    blogs = db.relationship("Blog",backref="category",lazy=True)


class Blog(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    title=db.Column(db.String(100),nullable=False)
    content=db.Column(db.Text,nullable=False)
    blog_image=db.Column(db.String(20),nullable=False,default="blog.png")
    slug=db.Column(db.String(32),nullable=False)
    creted_at=db.Column(db.DateTime,nullable=False,default=datetime.utcnow)
    user_id = db.Column(db.Integer,db.ForeignKey("user.id"),nullable=False)
    category_id = db.Column(db.Integer,db.ForeignKey("category.id"),nullable=False)



if __name__ == "__main__":
    app.run(debug=True)