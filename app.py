from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
import os
import sqlite3

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError
from flask import (
    Flask,
    current_app,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "instance" / "app.db"))
DEFAULT_USERNAMES = ("arat", "tara")
ACCESS_TOKEN_SECONDS = 180
REFRESH_TOKEN_SECONDS = 60 * 60
JWT_ALGORITHM = "HS256"


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev-change-me"),
        AUTH_COOKIE_SECURE=os.environ.get("AUTH_COOKIE_SECURE", "false").lower()
        == "true",
    )

    @app.before_request
    def load_authenticated_user():
        g.current_user = None
        g.access_token_to_set = None

        access_payload = decode_token(request.cookies.get("access_token"), "access")
        if access_payload is not None:
            g.current_user = get_user_by_id(access_payload.get("sub"))
            return

        refresh_payload = decode_token(request.cookies.get("refresh_token"), "refresh")
        if refresh_payload is None:
            return

        user = get_user_by_id(refresh_payload.get("sub"))
        if user is None:
            return

        g.current_user = user
        g.access_token_to_set = create_token(user, "access")

    @app.after_request
    def persist_refreshed_access_token(response):
        access_token = getattr(g, "access_token_to_set", None)
        if access_token:
            set_auth_cookie(response, "access_token", access_token, ACCESS_TOKEN_SECONDS)
        return response

    @app.context_processor
    def inject_current_user():
        return {"current_user": getattr(g, "current_user", None)}

    @app.teardown_appcontext
    def close_db(error=None):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.route("/")
    def index():
        if g.current_user is not None:
            return redirect(url_for("posts"))
        return redirect(url_for("login"))

    @app.route("/register", methods=("GET", "POST"))
    def register():
        if g.current_user is not None:
            return redirect(url_for("posts"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            if not username or not password:
                return render_template(
                    "register.html",
                    message="아이디와 비밀번호를 모두 입력해 주세요.",
                    category="error",
                )

            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                return render_template(
                    "register.html",
                    message="이미 사용 중인 아이디입니다.",
                    category="error",
                )

            return redirect(
                url_for(
                    "login",
                    message="회원가입이 완료되었습니다. 로그인해 주세요.",
                    category="success",
                )
            )

        return render_template("register.html")

    @app.route("/login", methods=("GET", "POST"))
    def login():
        if g.current_user is not None:
            return redirect(url_for("posts"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = (
                get_db()
                .execute("SELECT * FROM users WHERE username = ?", (username,))
                .fetchone()
            )

            if user is None or not check_password_hash(user["password_hash"], password):
                return render_template(
                    "login.html",
                    message="아이디 또는 비밀번호가 올바르지 않습니다.",
                    category="error",
                )

            response = make_response(
                redirect(url_for("posts", message="로그인되었습니다.", category="success"))
            )
            set_login_cookies(response, user)
            return response

        return render_template("login.html")

    @app.route("/logout", methods=("POST",))
    def logout():
        response = make_response(
            redirect(url_for("login", message="로그아웃되었습니다.", category="success"))
        )
        clear_auth_cookies(response)
        return response

    @app.route("/posts")
    @login_required
    def posts():
        rows = (
            get_db()
            .execute(
                """
            SELECT posts.id, posts.user_id, posts.title, posts.content, posts.created_at, users.username
            FROM posts
            JOIN users ON users.id = posts.user_id
            ORDER BY posts.created_at DESC, posts.id DESC
            """
            )
            .fetchall()
        )
        return render_template("posts.html", posts=rows)

    @app.route("/posts/new", methods=("GET", "POST"))
    @login_required
    def new_post():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            content = request.form.get("content", "").strip()

            if not title or not content:
                return render_template(
                    "post_form.html",
                    post=None,
                    message="제목과 내용을 모두 입력해 주세요.",
                    category="error",
                )

            db = get_db()
            db.execute(
                "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
                (g.current_user["id"], title, content),
            )
            db.commit()
            return redirect(
                url_for("posts", message="게시글이 등록되었습니다.", category="success")
            )

        return render_template("post_form.html", post=None)

    @app.route("/posts/<int:post_id>/edit", methods=("GET", "POST"))
    @login_required
    def edit_post(post_id):
        post = get_post(post_id)
        if post is None:
            return redirect(
                url_for("posts", message="게시글을 찾을 수 없습니다.", category="error")
            )

        if post["user_id"] != g.current_user["id"]:
            return redirect(
                url_for(
                    "posts",
                    message="본인이 작성한 글만 수정할 수 있습니다.",
                    category="error",
                )
            )

        if request.method == "POST":
            title = request.form.get("title", "").strip()
            content = request.form.get("content", "").strip()

            if not title or not content:
                return render_template(
                    "post_form.html",
                    post=post,
                    message="제목과 내용을 모두 입력해 주세요.",
                    category="error",
                )

            db = get_db()
            db.execute(
                "UPDATE posts SET title = ?, content = ? WHERE id = ?",
                (title, content, post_id),
            )
            db.commit()
            return redirect(
                url_for("posts", message="게시글이 수정되었습니다.", category="success")
            )

        return render_template("post_form.html", post=post)

    @app.route("/posts/<int:post_id>/delete", methods=("POST",))
    @login_required
    def delete_post(post_id):
        post = get_post(post_id)
        if post is None:
            return redirect(
                url_for("posts", message="게시글을 찾을 수 없습니다.", category="error")
            )

        if post["user_id"] != g.current_user["id"]:
            return redirect(
                url_for(
                    "posts",
                    message="본인이 작성한 글만 삭제할 수 있습니다.",
                    category="error",
                )
            )

        db = get_db()
        db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
        db.commit()
        return redirect(
            url_for("posts", message="게시글이 삭제되었습니다.", category="success")
        )

    with app.app_context():
        init_db()

    return app


def set_login_cookies(response, user):
    g.access_token_to_set = None
    set_auth_cookie(
        response, "access_token", create_token(user, "access"), ACCESS_TOKEN_SECONDS
    )
    set_auth_cookie(
        response, "refresh_token", create_token(user, "refresh"), REFRESH_TOKEN_SECONDS
    )
    if request.cookies.get("session"):
        response.delete_cookie(current_app.config.get("SESSION_COOKIE_NAME", "session"))


def set_auth_cookie(response, name, value, max_age):
    response.set_cookie(
        name,
        value,
        max_age=max_age,
        httponly=True,
        samesite="Lax",
        secure=current_app.config["AUTH_COOKIE_SECURE"],
    )


def clear_auth_cookies(response):
    g.access_token_to_set = None
    for name in ("access_token", "refresh_token", "session"):
        if request.cookies.get(name):
            response.delete_cookie(name)


def create_token(user, token_type):
    now = datetime.now(timezone.utc)
    expires_in = (
        timedelta(seconds=ACCESS_TOKEN_SECONDS)
        if token_type == "access"
        else timedelta(seconds=REFRESH_TOKEN_SECONDS)
    )
    payload = {
        "sub": str(user["id"]),
        "username": user["username"],
        "type": token_type,
        "iat": now,
        "exp": now + expires_in,
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm=JWT_ALGORITHM)


def decode_token(token, expected_type):
    if not token:
        return None

    try:
        payload = jwt.decode(
            token, current_app.config["SECRET_KEY"], algorithms=[JWT_ALGORITHM]
        )
    except (ExpiredSignatureError, InvalidTokenError):
        return None

    if payload.get("type") != expected_type:
        return None
    return payload


def get_user_by_id(user_id):
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return None

    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_db():
    if "db" not in g:
        DATABASE.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
        """
    )
    seed_default_users(db)
    db.commit()


def seed_default_users(db):
    for username in DEFAULT_USERNAMES:
        db.execute(
            "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
            (username, generate_password_hash(username)),
        )


def get_post(post_id):
    post = (
        get_db()
        .execute(
            """
        SELECT posts.*, users.username
        FROM posts
        JOIN users ON users.id = posts.user_id
        WHERE posts.id = ?
        """,
            (post_id,),
        )
        .fetchone()
    )
    if post is None:
        return None
    return post


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.current_user is None:
            response = make_response(
                redirect(url_for("login", message="로그인이 필요합니다.", category="error"))
            )
            clear_auth_cookies(response)
            return response
        return view(**kwargs)

    return wrapped_view


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
