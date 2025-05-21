# app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

def create_app():
    app = Flask(__name__, static_folder="../static")

    # JWT config
    app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
    app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token"
    app.config["JWT_COOKIE_SECURE"] = False  # True untuk HTTPS production
    app.config["JWT_COOKIE_SAMESITE"] = "Strict"
    app.config["JWT_COOKIE_CSRF_PROTECT"] = False  # atau True jika pakai CSRF

    # Konfigurasi Database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/autocutting_pmld'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = '12345'
    
    # Konfigurasi Email
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'tugaspmld@gmail.com'
    app.config['MAIL_PASSWORD'] = 'bsoo tkrg btrs kbrt'

    jwt = JWTManager(app)
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    mail.init_app(app)

    # Aktifkan CORS
    CORS(app, supports_credentials=True, origins=["http://localhost:3000"])


    # Registrasi blueprint
    from app.routes import analyze_bp, project_bp, auth_bp, user_bp
    app.register_blueprint(analyze_bp)
    app.register_blueprint(project_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)

    return app
