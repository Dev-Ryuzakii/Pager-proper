module.exports = {
  apps: [{
    name: 'pager-backend',
    script: 'fastapi_mobile_backend_postgresql.py',
    interpreter: '/home/blackops/Pager-proper/venv/bin/python3',
    cwd: '/home/blackops/Pager-proper',
    autorestart: true,
    max_restarts: 10,
    restart_delay: 4000,
    env: {
      PYTHONUNBUFFERED: '1',
      PORT: '8010',
      DATABASE_URL: 'postgresql://secure_user:secure_password_2024@127.0.0.1:5432/secure_messaging'
    },
    error_file: '/home/blackops/Pager-proper/logs/error.log',
    out_file: '/home/blackops/Pager-proper/logs/out.log',
    merge_logs: true
  }]
}
