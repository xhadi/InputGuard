import json
from pathlib import Path

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import User
from app.password_utils import hash_password, verify_password
from security.gateway import process_request


router = APIRouter()
templates = Jinja2Templates(directory="frontend/pages")


def _envelope(success: bool, blocked: bool, message: str, reason: str | None = None) -> dict:
    return {"success": success, "blocked": blocked, "message": message, "reason": reason}


@router.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse(request, "register.html")


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@router.post("/api/register")
async def api_register(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    data = {"username": username, "password": password}

    if settings.SECURITY_ENABLED:
        result = process_request(data=data)
        if result["is_blocked"]:
            return _envelope(
                False,
                True,
                "Request blocked by InputGuard",
                result.get("reason"),
            )

    if db.query(User).filter(User.username == username).first():
        return _envelope(False, False, "Username already taken")

    hashed_password = hash_password(password)
    user = User(username=username, password=hashed_password)
    db.add(user)
    db.commit()

    return _envelope(True, False, "Registration successful")


@router.post("/api/login")
async def api_login(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    data = {"username": username, "password": password}

    if settings.SECURITY_ENABLED:
        result = process_request(data=data)
        if result["is_blocked"]:
            return _envelope(
                False,
                True,
                "Request blocked by InputGuard",
                result.get("reason"),
            )

    user = db.query(User).filter(User.username == username).first()

    if user and verify_password(password, user.password):
        return _envelope(True, False, "Login successful")

    return _envelope(False, False, "Invalid credentials")


@router.get("/api/threat-log")
async def api_threat_log():
    log_path = Path(settings.LOG_FILE)
    threats = []

    if log_path.exists():
        for line in log_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                threats.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return {"threats": threats}
