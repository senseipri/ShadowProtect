# ShadowProtect

Monorepo scaffold for ShadowMesh.

## Structure

- `backend/` - Python backend (virtual environment in `backend/.venv`)
- `frontend/` - Next.js 14 app (TypeScript + Tailwind + App Router)

## Backend Setup

```powershell
python -m venv backend/.venv
backend/.venv/Scripts/pip install fastapi uvicorn websockets pydantic aiosqlite python-multipart scikit-learn numpy watchdog pyyaml
```

## Frontend Setup

```powershell
cd frontend
pnpm install
pnpm dev
```
