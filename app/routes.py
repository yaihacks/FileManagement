import os
from flask import render_template, url_for, flash, redirect, request, send_from_directory, jsonify, current_app
from app import app, db, bcrypt, logger
from app.models import User, File
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
import uuid
import hashlib
from datetime import datetime
import threading
from pathlib import Path

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'zip', 'rar', 'mp4', 'mp3'}
CHUNK_SIZE = 1024 * 1024 * 5  # 5MB chunks

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

@app.route("/")
def index():
    return redirect(url_for('login'))

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    
    return render_template('login.html')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/dashboard")
@login_required
def dashboard():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', files=files)

@app.route("/upload/chunk", methods=['POST'])
@login_required
def upload_chunk():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    chunk_number = int(request.form.get('chunk', 0))
    total_chunks = int(request.form.get('total_chunks', 0))
    file_id = request.form.get('file_id', '')
    
    if not file_id:
        file_id = str(uuid.uuid4())
    
    app_root = os.path.abspath(os.path.dirname(current_app.root_path))
    upload_folder = os.path.join(app_root, 'app', 'static', 'uploads')
    os.makedirs(upload_folder, exist_ok=True)
    
    temp_dir = os.path.join(upload_folder, 'temp', file_id)
    os.makedirs(temp_dir, exist_ok=True)
    
    chunk_path = os.path.join(temp_dir, f'chunk_{chunk_number}')
    logger.info(f"Saving chunk {chunk_number} to: {chunk_path}")
    file.save(chunk_path)
    
    uploaded_chunks = len(os.listdir(temp_dir))
    if uploaded_chunks == total_chunks:
        
        final_filename = secure_filename(request.form.get('filename'))
        unique_filename = f"{file_id}_{final_filename}"
        final_path = os.path.join(upload_folder, unique_filename)
        
        with open(final_path, 'wb') as outfile:
            for i in range(total_chunks):
                chunk_path = os.path.join(temp_dir, f'chunk_{i}')
                with open(chunk_path, 'rb') as infile:
                    outfile.write(infile.read())
        
        
        for chunk_file in os.listdir(temp_dir):
            os.remove(os.path.join(temp_dir, chunk_file))
        os.rmdir(temp_dir)
        
        
        file_size = os.path.getsize(final_path)
        file_hash = get_file_hash(final_path)
        
        new_file = File(
            filename=unique_filename,
            original_filename=final_filename,
            file_path=final_path,
            file_type=file.content_type,
            file_size=file_size,
            file_hash=file_hash,
            user_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': new_file.id
        }), 201
    
    return jsonify({
        'message': 'Chunk uploaded successfully',
        'file_id': file_id,
        'chunks_received': uploaded_chunks,
        'total_chunks': total_chunks
    }), 202

@app.route("/upload/status/<file_id>")
@login_required
def upload_status(file_id):
    temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp', file_id)
    if not os.path.exists(temp_dir):
        return jsonify({'error': 'Upload not found'}), 404
    
    chunks_received = len(os.listdir(temp_dir))
    return jsonify({
        'chunks_received': chunks_received
    })

@app.route("/upload", methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        
        
        app_root = os.path.abspath(os.path.dirname(current_app.root_path))
        upload_folder = os.path.join(app_root, 'app', 'static', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)
        
        file_path = os.path.join(upload_folder, unique_filename)
        logger.info(f"Saving file to: {file_path}")
        file.save(file_path)
        
        new_file = File(
            filename=unique_filename,
            original_filename=filename,
            file_path=file_path,
            file_type=file.content_type,
            file_size=os.path.getsize(file_path),
            user_id=current_user.id
        )
        db.session.add(new_file)
        db.session.commit()
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file_id': new_file.id
        }), 201
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route("/files/<int:file_id>", methods=['GET'])
@login_required
def get_file(file_id):
    logger.info(f"Get file request received for file_id: {file_id} by user: {current_user.email}")
    
    file = File.query.get_or_404(file_id)
    logger.info(f"File record found: {file.filename}")
    
    if file.user_id != current_user.id:
        logger.warning(f"Unauthorized access attempt to file {file_id} by user {current_user.email}")
        return jsonify({'error': 'Unauthorized'}), 403
    
    file_path = file.file_path
    logger.info(f"Attempting to serve file from path: {file_path}")
    
    if not os.path.exists(file_path):
        logger.error(f"File not found on disk at path: {file_path}")
        return jsonify({'error': 'File not found on disk'}), 404
    
    
    directory = os.path.abspath(os.path.dirname(file_path))
    filename = os.path.basename(file_path)
    logger.info(f"Serving file from absolute directory: {directory}, filename: {filename}")
    
    try:
        app_root = os.path.abspath(os.path.dirname(current_app.root_path))
        directory = os.path.join(app_root, 'app', 'static', 'uploads')
        logger.info(f"Final directory path: {directory}")
        
        if not os.path.exists(os.path.join(directory, filename)):
            logger.error(f"File not found at {os.path.join(directory, filename)}")
            return jsonify({'error': 'File not found at expected location'}), 404
            
        return send_from_directory(
            directory,
            filename,
            as_attachment=True,
            download_name=file.original_filename
        )
    except Exception as e:
        logger.error(f"Error serving file {file_id}: {str(e)}")
        return jsonify({'error': f'Error serving file: {str(e)}'}), 500

@app.route("/files/<int:file_id>", methods=['DELETE'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        os.remove(file.file_path)
        db.session.delete(file)
        db.session.commit()
        return jsonify({'message': 'File deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500 