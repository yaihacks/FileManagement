import os
from datetime import timedelta

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-here')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024 * 1024  # 5GB max total file size
    UPLOAD_CHUNK_SIZE = 5 * 1024 * 1024  # 5MB chunk size
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip', 'rar', 'mp4', 'mp3'}
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', 'app/static/uploads')
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    
    RATELIMIT_DEFAULT = "200 per day;50 per hour;1 per second"
    RATELIMIT_STORAGE_URL = "memory://"
    
    SECURE_HEADERS = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self'"
    }

class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///site.db')
    
class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'postgresql://user:password@localhost/dbname')
    
    # Production security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # SSL/TLS settings
    SSL_REDIRECT = True
    
    # Logging
    LOG_TO_STDOUT = os.getenv('LOG_TO_STDOUT', 'false').lower() in ['true', 'on', '1']
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    
    # File storage settings
    UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER', '/var/www/uploads')
    BACKUP_FOLDER = os.getenv('BACKUP_FOLDER', '/var/www/backups')
    
    # Cache settings
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/1')
    
    # Background task queue
    CELERY_BROKER_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/2')
    CELERY_RESULT_BACKEND = os.getenv('REDIS_URL', 'redis://localhost:6379/2') 