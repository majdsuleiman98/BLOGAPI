from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_restful import Resource, Api, reqparse
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required,logout_user




app = Flask(__name__)
app.config["SECRET_KEY"]="a997d5efb248bb348fa26b4e55ee8c01e16d154cfa36de10591b18e449d8f70f"
app.config["SQLALCHEMY_DATABASE_URI"] = 'mysql+mysqlconnector://root:''@localhost/blog'
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
api = Api(app)



class User(db.Model,UserMixin):
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

class RegistrationResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('fname', type=str, required=True)
        parser.add_argument('lname', type=str, required=True)
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()

        hashed_password = bcrypt.generate_password_hash(args['password']).decode("utf-8")
        user = User(
            fname=args['fname'],
            lname=args['lname'],
            username=args['username'],
            email=args['email'],
            password=hashed_password,
        )
        db.session.add(user)
        db.session.commit()
        return {'message': f'Account created successfully for {args["username"]}'}

class LoginResource(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('email', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()

        user = User.query.filter_by(email=args['email']).first()
        if user and bcrypt.check_password_hash(user.password, args['password']):
            login_user(user)
            return {'message': 'Login successful'}
        else:
            return {'error': 'Login unsuccessful. Please check credentials'}, 401

api.add_resource(RegistrationResource, '/register')
api.add_resource(LoginResource, '/login')   

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LogoutResource(Resource):
    @login_required
    def post(self):
        logout_user()
        return {"message": "User logged out successfully"}
    

api.add_resource(LogoutResource, "/api/logout", endpoint="logout")

class CategoryResource(Resource):
    #method_decorators = [login_required]  # Ensure that the user is logged in

    def get(self, category_id=None):
        if category_id is None:
            # Get all categories
            categories = Category.query.all()
            category_list = [{"id": category.id, "title": category.title, "description": category.description} for category in categories]
            return {"categories": category_list}
        else:
            # Get a specific category by ID
            category = Category.query.get(category_id)
            if category:
                return {"id": category.id, "title": category.title, "description": category.description}
            return {"error": "Category not found"}, 404
    #@login_required(message="You must be logged in to access this resource.")
    def post(self):
        if not current_user.is_authenticated:
            return {"error": "You must be logged in to access this resource."}, 403
        if not current_user.is_admin:
            return {"error": "Only admin users can create a category"}, 403
        
        parser = reqparse.RequestParser()
        parser.add_argument("title", type=str, required=True, help="Title is required")
        parser.add_argument("description", type=str, required=True, help="Description is required")
        args = parser.parse_args()

        category = Category(title=args["title"], description=args["description"])
        db.session.add(category)
        db.session.commit()
        return {"message": "Category created successfully"}, 201

    def put(self, category_id):
        if not current_user.is_authenticated:
            return {"error": "You must be logged in to access this resource."}, 403
        if not current_user.is_admin:
            return {"error": "Only admin users can update a category"}, 403

        category = Category.query.get(category_id)
        if not category:
            return {"error": "Category not found"}, 404

        parser = reqparse.RequestParser()
        parser.add_argument("title", type=str)
        parser.add_argument("description", type=str)
        args = parser.parse_args()

        if args["title"]:
            category.title = args["title"]
        if args["description"]:
            category.description = args["description"]

        db.session.commit()
        return {"message": "Category updated successfully"}

    def delete(self, category_id):
        if not current_user.is_authenticated:
            return {"error": "You must be logged in to access this resource."}, 403
        if not current_user.is_admin:
            return {"error": "Only admin users can delete a category"}, 403

        category = Category.query.get(category_id)
        if not category:
            return {"error": "Category not found"}, 404

        db.session.delete(category)
        db.session.commit()
        return {"message": "Category deleted successfully"}

api.add_resource(CategoryResource, "/api/categories/<int:category_id>", endpoint="category")
api.add_resource(CategoryResource, "/api/categories", endpoint="categories")


#Blog API

class BlogResource(Resource):
    parser = reqparse.RequestParser()
    parser.add_argument("title", type=str, required=True, help="Title is required")
    parser.add_argument("content", type=str, required=True, help="Content is required")
    parser.add_argument("category_id", type=int, required=True, help="Category ID is required")
    def get(self,blog_id=None):
        if blog_id is not None:
            # Get a specific blog by ID
            blog = Blog.query.get(blog_id)
            if blog:
                return {"id": blog.id, "title": blog.title, "content": blog.content, "user_id": blog.user_id,
                        "category_id": blog.category_id}
            return {"error": "Blog not found"}, 404
        else:
            # Get all blogs
            blogs = Blog.query.all()
            blog_list = [{"id": blog.id, "title": blog.title, "content": blog.content, "user_id": blog.user_id,
                        "category_id": blog.category_id} for blog in blogs]
            return {"blogs": blog_list}

    @login_required
    def post(self):
        args = self.parser.parse_args()

        blog = Blog(
            title=args["title"],
            content=args["content"],
            category_id=args["category_id"],
            slug=str(args["title"]).replace(" ", "-"),
            user_id=current_user.id
        )

        db.session.add(blog)
        db.session.commit()

        return {"message": "Blog created successfully"}, 201

    @login_required
    def put(self, blog_id):
        blog = Blog.query.get(blog_id)
        if not blog:
            return {"error": "Blog not found"}, 404

        if blog.user_id != current_user.id:
            return {"error": "You can only update your own blogs"}, 403

        args = self.parser.parse_args()

        blog.title = args["title"]
        blog.content = args["content"]
        blog.category_id = args["category_id"]

        db.session.commit()

        return {"message": "Blog updated successfully"}

    @login_required
    def delete(self, blog_id):
        blog = Blog.query.get(blog_id)
        if not blog:
            return {"error": "Blog not found"}, 404

        if blog.user_id != current_user.id:
            return {"error": "You can only delete your own blogs"}, 403

        db.session.delete(blog)
        db.session.commit()

        return {"message": "Blog deleted successfully"}


api.add_resource(BlogResource, "/api/blogs/<int:blog_id>", endpoint="blog")
api.add_resource(BlogResource, "/api/blogs", endpoint="blogs")




if __name__ == "__main__":
    app.run(debug=True)