# app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_mail import Mail
from flask_cors import CORS
from flask_bcrypt import Bcrypt

db = SQLAlchemy()
migrate = Migrate()
mail = Mail()

def create_app():
    app = Flask(__name__)

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
    CORS(app)

    bcrypt = Bcrypt(app)    
    jwt = JWTManager(app)
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)
    mail.init_app(app)


    # Registrasi blueprint
    from app.routes import analyze_bp, project_bp, auth_bp, user_bp
    app.register_blueprint(analyze_bp)
    app.register_blueprint(project_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)

    return app
