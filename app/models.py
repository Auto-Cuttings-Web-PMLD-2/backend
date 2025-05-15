from app import db
from sqlalchemy.orm import relationship
from datetime import date
from datetime import datetime

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    sandStoneCount = db.Column(db.Integer, nullable=False)
    sandStoneCoverage = db.Column(db.Float, nullable=False)
    siltStoneCount = db.Column(db.Integer, nullable=False)
    siltStoneCoverage = db.Column(db.Float, nullable=False)
    segmentedImageURL = db.Column(db.String(255), nullable=False)
    postDate = db.Column(db.Date, nullable=False, default=date.today)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = relationship('User', backref='projects')


    def __repr__(self):
        return f'<Project {self.name}>'
    
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    def __repr__(self):
        return f'<User {self.name}>'

