# File Management System

A secure file management system with user authentication and file upload capabilities built with Flask.

## Features

- User authentication (register/login)
- Secure password hashing
- File upload and storage
- File download
- File deletion
- Modern and responsive UI
- Secure file handling

## Setup

1. Clone the repository:

```bash
git clone <repository-url>
cd FileManagement
```

2. Create a virtual environment and activate it:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

3. Install the required packages:

```bash
pip3 install -r requirements.txt
```

4. Create a `.env` file in the root directory with the following content:

```
SECRET_KEY=your_secret_key_here
SQLALCHEMY_DATABASE_URI=sqlite:///site.db
UPLOAD_FOLDER=app/static/uploads
```

5. Run the application:

```bash
gunicorn -w 4 -b 127.0.0.1:8000 run:app
```

The application will be available at `http://localhost:8000`

## Usage

1. Register a new account using your email and password
2. Login with your credentials
3. Upload files using the upload form
4. View your uploaded files in the dashboard
5. Download or delete files as needed

## Security Features

- Password hashing using bcrypt
- Secure file storage with unique filenames
- User authentication required for file operations
- File type validation
- Maximum file size limit (16MB)
- Secure file paths

## Supported File Types

- Images (jpg, jpeg, png, gif)
- Documents (txt, pdf, doc, docx)

## Directory Structure

```
file_auth_system/
├── .env
├── requirements.txt
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes.py
│   ├── config.py
│   ├── static/
│   │   └── uploads/
│   └── templates/
│       ├── login.html
│       ├── register.html
│       └── dashboard.html
└── run.py
```

## Production Configuration

1. Set up environment variables in production:

```bash
export FLASK_ENV=production
export SECRET_KEY=your-secure-secret
export SQLALCHEMY_DATABASE_URI=postgresql://user:pass@localhost/dbname
export REDIS_URL=redis://localhost:6379/0
```

2. Set up Nginx as a reverse proxy:

```nginx
server {
    listen 80;
    server_name your_domain.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        client_max_body_size 5G;
    }
}
```

3. Set up monitoring and logging:

- Use Sentry for error tracking
- Set up Prometheus metrics
- Configure proper logging

4. Regular maintenance:

- Set up automated backups
- Implement file cleanup policies
- Monitor disk space usage
- Set up alerts for system metrics
