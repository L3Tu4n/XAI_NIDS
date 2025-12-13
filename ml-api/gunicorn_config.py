"""Gunicorn configuration file"""
import multiprocessing
import os

# Server socket
bind = "0.0.0.0:5000"
backlog = 2048

# Worker processes
workers = int(os.getenv('WORKERS', 4))
worker_class = 'sync'
worker_connections = 1000
timeout = 120
keepalive = 5

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'nids-ml-api'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# Preload app để tiết kiệm memory (tùy chọn)
preload_app = False  # Set False để mỗi worker load riêng model

# Post fork hook
def post_fork(server, worker):
    """Load model sau khi fork worker"""
    from app import init_service
    init_service()