# Live Server Setup

Steps to fix "DATABASE_URL not found" and "relation does not exist" on your live server.

---

## 1. Create `.env` file

`.env` is **not** in git (it's gitignored). You must create it manually on the server.

```bash
cd ~/Pager-proper
nano .env
```

Add (replace with your real PostgreSQL credentials):

```
DATABASE_URL=postgresql://USERNAME:PASSWORD@localhost:5432/secure_messaging
```

Or use separate variables:

```
DB_HOST=localhost
DB_PORT=5432
DB_NAME=secure_messaging
DB_USER=your_postgres_username
DB_PASSWORD=your_postgres_password
```

Save and exit.

---

## 2. Create database tables

The `users` and `user_sessions` tables do not exist yet. Run:

```bash
cd ~/Pager-proper
source venv/bin/activate
python3 create_admin_user.py init
```

You should see: `✅ Database tables created successfully!`

---

## 3. Create admin user

```bash
python3 create_admin_user.py create
```

---

## 4. Restart the backend

```bash
sudo systemctl restart pager_backend
```

## 5. Enable organization-aware Ollama decoys

Ollama must stay private on the VPS; do not expose port `11434` publicly.

```bash
ollama list
ollama pull qwen2.5:7b
curl http://127.0.0.1:11434/api/tags
```

Add these values to `~/Pager-proper/.env`:

```env
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:7b
DECOY_LLM=1
DECOY_LLM_MODEL=qwen2.5:7b
DECOY_LLM_CONTEXT_TIMEOUT=6
DECOY_LLM_TIMEOUT=20
DECOY_LLM_THREADS=6
DECOY_LLM_POOL=16
```

Then restart and follow the logs:

```bash
sudo systemctl restart ollama
sudo systemctl restart pager_backend
sudo journalctl -u pager_backend -n 100 -f
```

The startup log should include `LLM decoy pool warming in background`. If
Ollama is unavailable or rejects an output, messages continue using the
strict work-only fallback generator.

---

## Quick checklist

| Step | Command |
|------|---------|
| Create .env | `nano .env` (add DATABASE_URL with password) |
| Init tables | `python3 create_admin_user.py init` |
| Create admin | `python3 create_admin_user.py create` |
| Check Ollama | `curl http://127.0.0.1:11434/api/tags` |
| Restart app | `sudo systemctl restart pager_backend` |
