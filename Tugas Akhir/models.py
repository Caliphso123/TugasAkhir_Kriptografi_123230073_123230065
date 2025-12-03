from flask_sqlalchemy import SQLAlchemy
import datetime

db = SQLAlchemy() 

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    user_salt = db.Column(db.LargeBinary, nullable=False)
    id_hash = db.Column(db.String(120), unique=True, nullable=True)

    notes = db.relationship('Note', 
                            foreign_keys='Note.user_id', 
                            backref='owner', 
                            lazy='dynamic')

    deleted_notes = db.relationship('Note', 
                                    foreign_keys='Note.deleted_by_user_id', 
                                    backref='deleted_by', 
                                    lazy='dynamic')

    def __repr__(self):
        return f"<User {self.username}>"

class Note(db.Model):
    __tablename__ = 'note'
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=True)
    secret_code_hash = db.Column(db.String(255), nullable=True)
    data_type = db.Column(db.String(50), default='TEXT')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code_salt = db.Column(db.LargeBinary, nullable=True)
    hidden_payload_bytes = db.Column(db.LargeBinary, nullable=True) 
    encrypted_content = db.Column(db.LargeBinary, nullable=False)
    nonce = db.Column(db.LargeBinary, nullable=False)
    data_type = db.Column(db.String(50), default='TEXT')
    created_at = db.Column(db.DateTime, default=datetime.datetime.now(datetime.timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    deleted_at = db.Column(db.DateTime, nullable=True)
    deleted_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) 

    def __repr__(self):
        return f"<Note {self.id} Status: {'Deleted' if self.deleted_at else 'Active'}>"