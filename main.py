from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from functools import wraps
from flask import abort
import os

from forms import CreatePostForm
from flask_gravatar import Gravatar
from flask_wtf import FlaskForm

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
ckeditor = CKEditor(app)

##CONNECT TO DB

uri = os.getenv("DATABASE_URL", "sqlite:///blog1.db")  # or other relevant config var
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
# rest of connection code using the connection string `uri`

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(uri)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONFIGURE TABLES


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)

    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # ------------------------------------------------------
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = db.relationship("User", back_populates="posts")

    comments = db.relationship("Comment", back_populates="blogs")


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer(), primary_key=True)
    text = db.Column(db.Text, nullable=False)
    # ---------------------------------------------------------------#
    author_id = db.Column(db.Integer(), db.ForeignKey("users.id"))
    comment_author = db.relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer(), db.ForeignKey("blog_posts.id"))
    blogs = db.relationship("BlogPost", back_populates="comments")


db.create_all()


class CommentForm(FlaskForm):
    comment = CKEditorField('Comment', validators=[DataRequired()])
    submit = SubmitField('Submit a Comment')


class RegistrationForm(FlaskForm):
    email = StringField('Email:', validators=[Email(), DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    name = StringField('Name:', validators=[DataRequired()])
    submit = SubmitField("Submit")


class LoginForm(FlaskForm):
    email = StringField('Email:', validators=[Email(), DataRequired()])
    password = PasswordField('Password:', validators=[DataRequired()])
    submit = SubmitField("Submit")


class NewPostForm(FlaskForm):
    title = StringField('Title:', validators=[DataRequired()])
    subtitle = StringField('Subtitle:', validators=[DataRequired()])
    body = CKEditorField('Body', validators=[DataRequired()])
    img_url = StringField('Image Url:', validators=[DataRequired()])
    submit = SubmitField('Submit Post')


@login_manager.user_loader
def load_user(user_id):
    user = db.session.query(User).filter(User.id == user_id).first()
    return user


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()

    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            # return redirect(url_for('login', next=request.url))
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    reg_form = RegistrationForm(request.form)

    if request.method == 'POST' and reg_form.validate_on_submit():

        does_user_exist = db.session.query(User).filter_by(email=request.form.get('email')).first()
        if does_user_exist is None:
            hash_salted_password = generate_password_hash(password=request.form.get('password'),
                                                          method="pbkdf2:sha256",
                                                          salt_length=8)
            new_user = User(email=request.form.get('email'),
                            password=hash_salted_password,
                            name=request.form.get('name'))

            login_user(new_user)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts'))
        else:
            flash("Email already in use. Please log instead.")

    return render_template("register.html", form=reg_form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm(request.form)
    if request.method == 'POST' and login_form.validate_on_submit():
        print(request.form.get('email'))
        print(request.form.get('password'))

        user = db.session.query(User).filter_by(email=request.form.get('email')).first()
        if user is not None:
            if check_password_hash(user.password, request.form.get('password')):
                print(user.id)
                login_user(user)
                return redirect(url_for('get_all_posts'))
        else:
            flash('Incorrect email or password.')
    return render_template("login.html", form=login_form, logged_in=current_user.is_authenticated)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


# @app.route('/comment', methods=['GET', 'POST'])
# def comment():
#     if request.method == 'POST':
#         comment_ = request.form.get("comment")
#         print(request.form.get("postId"))
#
#         blog = db.session.query(BlogPost).filter_by(id=request.form.get("postId")).first()
#
#         new = Comment(text=comment_,
#                       comment_author=current_user,
#                       blogs=blog)
#
#         for p in blog.comments:
#             print(p.text)
#
#         db.session.add(new)
#         db.session.commit()
#         return render_template("post.html")


@app.route("/post/<int:post_id>", methods=['POST','GET'])
def show_post(post_id):
    print("show post")
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if request.method == 'POST':
        if current_user.is_authenticated:
            comment_ = request.form.get("comment")
            print(request.form.get("postId"))

            blog = db.session.query(BlogPost).filter_by(id=request.form.get("postId")).first()

            new = Comment(text=comment_,
                          comment_author=current_user,
                          blogs=blog)

            db.session.add(new)
            db.session.commit()
        else:
            return redirect(url_for('login'))

    return render_template("post.html", post=requested_post, form=form, blog=requested_post)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["POST", "GET"])
@admin_only
def add_new_post():
    form = NewPostForm()
    print(current_user.id)
    print(current_user.name)
    print(current_user.is_authenticated)
    if current_user.is_authenticated:
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    else:
        return redirect(url_for('login'))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(port=9000, debug=True)
