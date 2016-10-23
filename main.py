#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import re
import logging
import cgi

from lib.bcrypt import bcrypt

from google.appengine.ext import ndb

# Location of HTML templates
TEMPLATE_LOCATION = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 "templates")

# Gathering the templates
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(TEMPLATE_LOCATION),)

# ReEx pattern for inputs
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def verify_username(pass_phrase):
    """ Verifying the username input.

    :param pass_phrase: (Str) user name.
    :return: (Str) and error message of the validation failed or an empty
    string if the validation passed
    """

    if not USER_RE.match(pass_phrase):
        return "That wasn't a valid username."
    return ""


def verify_password(pass_phrase):
    """ Verifying the password input.

    :param pass_phrase: (Str) password.
    :return: (Str) and error message of the validation failed or an empty
    string if the validation passed
    """

    if not PASSWORD_RE.match(pass_phrase):
        return "That wasn't a valid password."
    return ""


def verify_email(pass_phrase):
    """ Verifying the email input

    :param pass_phrase: (Str) email address.
    :return: (Str) and error message of the validation failed or an empty
    string if the validation passed
    """

    if not EMAIL_RE.match(pass_phrase):
        return "That's not a valid email."
    return ""


def user_authentication(user_hashed_id):
    """ Validate the user id authentication.

    :param user_hashed_id: (str) hashed user id in.
    :return: (RegisterUser) RegisterUser entity if it exists.
    """

    user = RegisterUser.get_user(user_hashed_id)
    return user or None


class RegisterUser(ndb.Model):
    """ Adding a new user to the database.

    :param username: (str) username.
    :param hased_username: (str) Hashed username.
    :param password: (str) Hashed user's password.
    :param user_email: (str) user's email address
    """

    username = ndb.StringProperty(required=True)
    hashed_username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    user_email = ndb.StringProperty(required=True)
    signup_date = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_user(cls, user_id):
        """ Returns the entity of the user based on the given user id address"""
        return cls.query(cls.hashed_username == user_id).get()

    @classmethod
    def get_email(cls, email):
        """ Returns the entity of the user based on the given email address """
        return cls.query(cls.user_email == email).get()

    @classmethod
    def get_id(cls, user_id):
        """ Returns the entity of the user based on the given hased username
        address
        """
        try:
            user_key = cls.query(cls.hashed_username == user_id).get().key.id()
            return user_key
        except Exception as e:
            logging.error("Did not find the user:\n"+str(e))
            return None


class LikeIt(ndb.Model):
    """ database for storing the which user likes which blog.

    :param blog_id: (int) Entity's ID number of the blog.
    :param user_id: (int) Entity's ID number of the user.
    :param user_id: (str) Like of dislike the blog.
    """

    blog_id = ndb.IntegerProperty(required=True)
    user_id = ndb.IntegerProperty(required=True)
    likes = ndb.StringProperty(choices=["like", "dislike"])

    @classmethod
    def get_by_blog_id(cls, blog_id, user_id):
        """ Find the entity based on the blog's id and user's id

        :param blog_id: (int) blog id
        :param user_id: (int) user id
        :return: LikeIt entity  or None if it didn't find one
        """
        try:
            return cls.query(cls.blog_id == blog_id,
                             cls.user_id == user_id).get()

        except Exception as e:
            logging.info("Didn't find a vote for this user on this blog")
            return None

    @classmethod
    def get_by_user_id(cls, user_id):
        """ Find the entities based on the user's id.

        :param user_id: (int) blog id
        :return: List of LikeIt entity  or None if it didn't find one
        """
        try:
            return cls.query(cls.user_id == user_id).fetch()

        except Exception as e:
            logging.info("Didn't find a vote for this user on this blog")
            return None


class Comments(ndb.Model):
    """ database for storing the comments made by user on blogs.

    :param commenter: (str) username of the person who commented on the blog.
    :param blog_id: (int) blog's id which receiving the comment.
    :param commenter_id: (int) commenter's id which posting the comment.
    :param comment: (Str) Comment.
    """

    commenter = ndb.StringProperty(required=True)
    blog_id = ndb.IntegerProperty(required=True)
    commenter_id = ndb.IntegerProperty(required=True)
    comment = ndb.TextProperty(required=True)
    comment_date = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def get_all_comments(cls, blog_id):
        """ Find all the entities based on the blog's id.

        :param blog_id: (int) blog id
        :return: List of LikeIt entity or None if it didn't find one.
        """

        if blog_id:
            query = cls.query(cls.blog_id == blog_id).order(
                -Comments.comment_date).fetch()
            return query


class NewPost(ndb.Model):
    """ Adding a new blog to the database.

    :param title: (str) Title of the blog.
    :param blogger: (str) Username of the person who is posting the blog.
    :param blog: (str) Content of the blog.
    :param user_id: (int) blogger's id.
    :param description: (str) description of the blog.
    :param tag: (str) blog's tag.
    :param likes: (int) number of likes that this blog received.
    :param dislikes: (int) number of dislikes that this blog received.
    :param rate: (int) This blog's rate based on likes, dislikes and date (WP)
    """

    title = ndb.StringProperty(required=True)
    blogger = ndb.StringProperty(required=True)
    blog = ndb.TextProperty(required=True)
    user_id = ndb.IntegerProperty(required=True)
    description = ndb.StringProperty(required=True)
    tag = ndb.StringProperty()
    likes = ndb.IntegerProperty(default=0)
    dislikes = ndb.IntegerProperty(default=0)
    rate = ndb.IntegerProperty(default=0)
    post_date = ndb.DateTimeProperty(auto_now_add=True)
    edit_date = ndb.DateTimeProperty(auto_now=True)

    @classmethod
    def get_user(cls, user_id):
        """ Find the blog entity based on user's id

        :param user_id: (int) user id
        :return: (NewPost) NewPost entity of None.
        """
        return cls.query(cls.user_id == user_id).get()

    @classmethod
    def get_all_blogs(cls, user):
        """ Find all the blog entities based on user's id.

        :param user_id: (int) user id
        :return: (NewPost) NewPost entities of None.
        """
        if user:
            query = cls.query(cls.user_id == user).order(
                -NewPost.post_date).fetch()
        else:
            query = cls.query().order(-NewPost.post_date).fetch()
        return query


class Handler(webapp2.RedirectHandler):
    """ Handling the rendering the template.
    """

    def write(self, *args, **kwargs):
        self.response.write(*args, **kwargs)

    @staticmethod
    def render_str(template, **parms):
        t = jinja_env.get_template(template)
        return t.render(parms)

    def render(self, template, **kw):
        return self.write(self.render_str(template, **kw))


class MainHandler(Handler):
    def get(self):
        # Get the user's id cookie
        user_id = self.request.cookies.get("user_id")

        # Make sure the user's id cookie is valid and there is a user with
        # that user_id exists in the database
        if user_id and user_authentication(user_id):
            self.redirect('/welcome')
        # If can't find the user id that means no user is logged in,
        # so redirect the user to the log in page
        else:
            self.render("index.html")

    def post(self):
        # Redirect the user to the Log in or Signup page based on their request.
        action = self.request.get("new_action")

        if action == "Login":
            self.redirect("/login")
        else:
            self.redirect("/signup")


class WelcomeHandler(Handler):
    """ Load the welcome page html and handle its posts.
    """

    def get(self):
        user_id = self.request.cookies.get("user_id")

        if user_id:
            user = user_authentication(user_id)

            if user:
                # If the user is valid, find and render the blogs.
                username = user.username
                blogs = NewPost.get_all_blogs(user=None)

                self.render_blogs(username=username,
                                  blogs=blogs,
                                  )

            # Move the user to the home page if they're not logged in.
            else:
                self.redirect("/")
        else:
            self.redirect("/")

    def post(self):
        action = self.request.get("new_action")

        # Redirect the user according to their request of logging out or
        # trying to post a new blog.
        if action == "Logout":
            self.redirect("/logout")
            return
        elif action == "New Post":
            self.redirect("/new-post")
            return
        else:
            user_id = self.request.cookies.get("user_id")
            user = RegisterUser.get_user(user_id)
            username = user.username
            blog_selection = self.request.get("blogs")

            if blog_selection == "Show All Blogs":
                # Find the all blogs
                blogs = NewPost.get_all_blogs(user=None)

            elif blog_selection == "Show My Blogs":
                # Find the user's personal blogs
                blogs = NewPost.get_all_blogs(RegisterUser.get_id(user_id))

            else:
                user_key_id = int(RegisterUser.get_user(user_id).key.id())
                liked_blogs = LikeIt.get_by_user_id(user_key_id)
                blogs = []

                # Find the user's favorites blogs
                for i in liked_blogs:
                    if i.likes == "like":
                        blog = NewPost.get_by_id(i.blog_id)
                        if blog:
                            blogs.append(blog)

            self.render_blogs(username=username,
                              blogs=blogs,
                              )

    # Render the home page and populate it with the selected blogs
    def render_blogs(self, username, blogs):
            self.render("welcome.html",
                        username=username,
                        blogs=blogs,
                        logged_in=True
                        )


class LogoutHandler(Handler):
    """ Log the user out and delete the user's id cookie.
    """

    def get(self):
        self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")
        self.redirect("/")


class SignUpHandler(Handler):
    """ Rendering the Sign Up page and validating the inputs.
    """

    def get(self):
        self.render('signup.html', logged_in=False)

    def post(self):

        # Collect the registration info from the form
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        # Validating the info
        username_error = verify_username(username)
        password_error = verify_password(password)
        email_error = verify_email(email)

        if password != verify:
            verify_error = "Your passwords didn't match."
        else:
            verify_error = ""

        # If the validation has failed return to the registration page and
        # repopulate the page with already imported info
        if (username_error or password_error or verify_error or
                email_error):
            self.render('signup.html',
                        username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email_error=email_error,
                        old_username=username,
                        old_email=email)
        else:
            # Check the database to see if there a account with the similar
            # username and/or email address
            if RegisterUser.get_user(username):
                username_error = "This username is already exists"
            if RegisterUser.get_email(email):
                email_error = "This email address already exits"

            # If username or email already exists, error out
            if username_error or email_error:
                self.render('signup.html',
                            username_error=username_error,
                            email_error=email_error,
                            old_username=username,
                            old_email=email)
            else:
                # Storing the new user into the database
                hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
                hashed_user = bcrypt.hashpw(username, bcrypt.gensalt())

                new_user = RegisterUser(hashed_username=hashed_user,
                                        username=username,
                                        password=hashed_password,
                                        user_email=email)
                new_user.put()

                # Redirecting the user to the homepage
                self.response.set_cookie('user_id', hashed_user)
                self.redirect('/')
                return


class LoginHandler(Handler):
    """ Load the log in page and handle its post requests"""

    def get(self):
        user_id = self.request.cookies.get("user_id")
        # If the user is already logged in, send the user to the home page
        if not user_id or not user_authentication(user_id):
            self.render("login.html")
        else:
            self.redirect("/welcome")

    def post(self):
        # Get input from user
        user_id = self.request.get("username")
        password = self.request.get("password")

        error_message = ""
        returned_user = None

        # Check the username and password
        if user_id and password:
            user = RegisterUser.query(RegisterUser.username == user_id).get()
            # If the user exists
            if user:
                # get the hashed password from database
                check = user.password
                # if the input password passed checkpoint, set the user
                if bcrypt.hashpw(password, check) == check:
                    returned_user = user
                else:
                    # If the username and the password DO NOT match,
                    # return to login with appropriate msg
                    error_message = "Username and Password didn't match."
            else:
                # If DID NOT find the user, return to login with appropriate msg
                error_message = "Did not find an account with this username"
        else:
            # If the user DOES NOT exist, return to login with appropriate msg
            error_message = "Both username and password are required!"

        if error_message:
            self.render("login.html", error=error_message)
        else:
            self.response.set_cookie('user_id',
                                     returned_user.hashed_username,
                                     path="/")
            self.redirect('/welcome')


class NewBlogPostHandler(Handler):
    """ Load the New Post Blog Page and handle its request."""

    def get(self):

        # If the user is not logged in send the user to the log in page.
        user_id = self.request.cookies.get("user_id")
        if not user_id or not user_authentication(user_id):
            self.redirect("/login")
        else:
            self.render('new_post.html', logged_in=True)

    def post(self):
        """ Add the blog post to the data base.
        """

        user_id = self.request.cookies.get("user_id")

        # If the user cookie doesn't exist or the user doesn't exist in the
        # database, redirect the user to the login page
        if not user_id or not user_authentication(user_id):
            self.redirect("/login")
            return

        # Getting the blog post info from the form
        title = self.request.get('title')
        blog = self.request.get('blog')
        description = self.request.get('description')
        tags = self.request.get('tags')
        blogger = RegisterUser.get_user(user_id)
        username = blogger.username

        # Making sure user inputs all the required inputs.
        if not title or not blog or not blogger or not description:
            if not title:
                title_error = "Title is required to submit the blog"
            else:
                title_error = ""
            if not blog:
                blog_error = "Blog can't be empty"
            else:
                blog_error = ""
            if not description:
                des_error = "Description of the blog  is required to submit " \
                            "the blog"
            else:
                des_error = ""

            # If any of the inputs are missing, stay on the New Blog POst page
            self.render('new_post.html',
                        old_title=title,
                        title_error=title_error,
                        blog_value=blog,
                        blog_error=blog_error,
                        old_des=description,
                        des_error=des_error,
                        old_tags=tags,
                        logged_in=True)
            return

        # If the blog's inputs are valid, add the blog to the database.
        new_post = NewPost(title=cgi.escape(title, quote=True),
                           blogger=username,
                           blog=cgi.escape(blog, quote=True),
                           user_id=RegisterUser.get_id(user_id),
                           description=cgi.escape(description, quote=True),
                           tag=cgi.escape(tags, quote=True))

        new_post.put()

        # Once the blog has been added to the database, redirect the user to
        # newly created the blog post page
        self.redirect("/{}".format(new_post.key.id()))


class ViewBlogPostHandler(Handler):
    """ Load and render the blog post"""

    def get(self, blog_id):
        """ Render the blog post.

        :param blog_id: (int) blog id number.
        """

        blog = NewPost.get_by_id(int(blog_id))

        # If the blog id is not found redirect the user to 404 page
        if not blog:
            self.redirect('/foo-bar')
            return

        # Before loading the page, setting up some restriction for if user is
        #  valid for commenting, liking, disliking, or editing the post.
        user_id = self.request.cookies.get("user_id")
        if RegisterUser.get_id(user_id):
            show_comment = True

            blog_user_id = blog.user_id
            user_key_id = int(RegisterUser.get_user(user_id).key.id())
            already_voted = LikeIt.get_by_blog_id(int(blog_id), user_key_id)

            if blog_user_id == RegisterUser.get_user(user_id).key.id():
                show_like_button = False
                can_edit = True
            else:
                show_like_button = True
                can_edit = False

        else:
            show_comment = False
            show_like_button = True
            can_edit = False
            already_voted = False
            user_key_id = None

        author = RegisterUser.get_by_id(blog.user_id)
        posted_date = str(blog.post_date)
        posted_date = posted_date.split(" ")[0]

        # Get the comments if they exists
        comments = Comments.get_all_comments(int(blog_id))

        self.render('view-post.html',
                    blog=blog, 
                    show_comment=show_comment,
                    show_likes=show_like_button,
                    username=author.username,
                    post_date=posted_date,
                    comments=comments,
                    already_voted=already_voted,
                    can_edit=can_edit,
                    logged_in=True,
                    user_key=user_key_id)

    def post(self, *args):
        """ Handling the likes, dislike, comments, and edit requests."""

        blog_id = args[0]
        like = self.request.get("likeIt")
        edit = self.request.get("edit")
        comment = self.request.get("blogComment")

        user_id = self.request.cookies.get("user_id")
        user = RegisterUser.get_user(user_id)

        if edit:
            self.redirect("/edit-post/{}".format(blog_id))
            return

        if like and user:

            target_blog = NewPost.get_by_id(int(blog_id))
            if target_blog.user_id == user.key.id():
                self.render("/{0}".format(blog_id),
                            like_error="This is your own blog. You can't ")
                return

            if LikeIt.get_by_blog_id(target_blog.user_id, user.key.id()):
                self.render("/{0}".format(blog_id),
                            like_error="You've already voted for this blog.")
                return

            if like == "likedIt":
                # add like to the database
                like = LikeIt(blog_id=int(blog_id),
                              user_id=user.key.id(),
                              likes="like")
                like.put()

                # Update the blog like/dislike
                target_blog.likes += 1
                target_blog.put()

                self.redirect("/{0}".format(blog_id))
                return
            else:
                like = LikeIt(blog_id=int(blog_id),
                              user_id=user.key.id(),
                              likes="dislike")
                like.put()

                # Update the blog like/dislike
                target_blog.dislikes += 1
                target_blog.put()

                self.redirect("/{0}".format(blog_id))
                return

        if comment:
            user = RegisterUser.get_user(user_id)

            # If no user is logged in, comment won't be added to the db. This
            #  is just in case if a black hat set a fake cookie as a user
            if user:

                commenter = user.username

                new_comment = Comments(commenter=commenter,
                                       blog_id=int(blog_id),
                                       commenter_id=int(user.key.id()),
                                       comment=comment,)
                new_comment.put()

        self.redirect("/{0}".format(blog_id))


class EditBlogPostHandler(Handler):
    """ Render and handle the Edit page requests."""

    def get(self, *args, **kwargs):

        user_id = self.request.cookies.get("user_id")
        user_key = RegisterUser.get_id(user_id)

        blog_id = args[0]
        target_blog = NewPost.get_by_id(int(blog_id))

        if not target_blog:
            self.redirect('/foo-bar')
            return

        blog_user_id = target_blog.user_id

        if blog_user_id != user_key:
            edit = False
        else:
            edit = True

        self.render("edit-blog.html",
                    can_edit=edit,
                    old_title=target_blog.title,
                    blog_value=target_blog.blog,
                    old_des=target_blog.description,
                    old_tags=target_blog.tag,
                    logged_in=True)

    def post(self, *args):

        user_id = self.request.cookies.get("user_id")
        user = user_authentication(user_id)

        blog_id = args[0]
        target_blog = NewPost.get_by_id(int(blog_id))

        # If user is not Authentication or not Authorization, move out
        if not user_id or not user or not user.key.id() == target_blog.user_id:
            self.redirect("/")
            return

        action = self.request.get("done")

        # Saving the changes on the blog in the database
        if action == "Save":

            title = self.request.get('title')
            blog = self.request.get('blog')
            description = self.request.get('description')
            tags = self.request.get('tags')

            target_blog.title = title
            target_blog.blog = blog
            target_blog.description = description
            target_blog.tag = tags

            target_blog.put()

            self.redirect("/{}".format(blog_id))
            return

        # If the user canceled, go back to the blog
        elif action == "Cancel":
            self.redirect("/{}".format(blog_id))
            return

        # If user requests to delete the post
        else:
            # Deleting its comments
            comments = Comments.get_all_comments(int(blog_id))
            for comment in comments:
                comment.key.delete()

            # Deleting the its likes
            likes = LikeIt.query(LikeIt.blog_id == int(blog_id)).fetch()
            for like in likes:
                like.key.delete()
            # Deleting the blog post
            target_blog.key.delete()

            self.redirect("/")


class EditCommentHandler(Handler):
    """ Render and handle the Edit Comment page  and its requests."""

    def get(self, comment_id):

        user_id = self.request.cookies.get("user_id")

        # If the user is not logged in, move it to login page
        if not user_id or not user_authentication(user_id):
            self.redirect('/login')
            return

        user_key = RegisterUser.get_id(user_id)
        comment = Comments.get_by_id(int(comment_id))

        if not comment:
            self.redirect("/foo-bar")
            return

        if comment.commenter_id == user_key:
            # If this is not the user's comment, kick the user out
            can_edit = True
        else:
            # If this is the user's comments, let him do his thing, it's cool.
            can_edit = False

        self.render("edit-comment.html",
                    comment=comment,
                    can_edit=can_edit)

    def post(self, comment_id):

        user_id = self.request.cookies.get("user_id")
        user_key = RegisterUser.get_id(user_id)
        comment = Comments.get_by_id(int(comment_id))

        if comment.commenter_id == user_key:
            # If this is the user's comments, let him do his thing, it's cool.
            can_edit = True
        else:
            # If this is not the user's comment, kick the user out
            can_edit = False

        action = self.request.get("done")

        # Saving the changes on the blog in the databse
        if action == "Save":

            if can_edit:

                new_comment = self.request.get('blogComment')
                comment.comment = new_comment

                comment.put()

            self.redirect("/{}".format(comment.blog_id))
            return

        # If the user canceled, go back to the blog
        elif action == "Cancel":
            self.redirect("/{}".format(comment.blog_id))
            return

        # If user requests to delete the post
        else:
            # Deleting the comments
            if can_edit:
                comment.key.delete()
            self.redirect("/{}".format(comment.blog_id))


class NotFoundHandler(Handler):
    """ If the requested blog does not exits, render 404 error page.
    """

    def get(self):
        self.render("blog-not-found.html")


app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignUpHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
    ('/welcome', WelcomeHandler),
    ('/new-post', NewBlogPostHandler),
    ('/([0-9]+)', ViewBlogPostHandler),
    ('/edit-post/([0-9]+)', EditBlogPostHandler),
    ('/edit-comment/([0-9]+)', EditCommentHandler),
    ('/foo-bar', NotFoundHandler),
], debug=True)
