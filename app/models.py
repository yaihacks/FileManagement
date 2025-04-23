from datetime import datetime
from app import db, login_manager
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    files = db.relationship('File', backref='owner', lazy=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    storage_used = db.Column(db.BigInteger, default=0)  # Total storage used in bytes
    is_active = db.Column(db.Boolean, default=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    original_filename = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime)
    file_type = db.Column(db.String(50))
    file_size = db.Column(db.BigInteger)
    file_hash = db.Column(db.String(64))
    mime_type = db.Column(db.String(100))
    is_public = db.Column(db.Boolean, default=False)
    download_count = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='active')  # active, deleted, processing
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    def __init__(self, **kwargs):
        super(File, self).__init__(**kwargs)
        if self.file_size and self.user_id:
            user = User.query.get(self.user_id)
            if user:
                user.storage_used += self.file_size
                db.session.add(user) 