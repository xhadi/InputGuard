import os

import bcrypt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set test environment before importing app modules.
os.environ["DATABASE_URL"] = "sqlite:///./test_inputguard.db"
os.environ["SECURITY_ENABLED"] = "False"
os.environ["LOG_FILE"] = "test_threats.log"

from app.database import Base, get_db
from app.main import app
from app.models import User


engine = create_engine(
    os.environ["DATABASE_URL"],
    connect_args={"check_same_thread": False},
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_and_teardown():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    if os.path.exists("test_inputguard.db"):
        os.remove("test_inputguard.db")
    if os.path.exists("test_threats.log"):
        os.remove("test_threats.log")


client = TestClient(app)


def test_login_page_returns_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_register_page_returns_html():
    response = client.get("/register")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_dashboard_page_returns_html():
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_register_success():
    response = client.post("/api/register", data={"username": "alice", "password": "secret"})
    assert response.status_code == 200
    body = response.json()
    assert body == {"success": True, "blocked": False, "message": "Registration successful", "reason": None}


def test_register_duplicate_username():
    client.post("/api/register", data={"username": "alice", "password": "secret"})
    response = client.post("/api/register", data={"username": "alice", "password": "secret"})
    assert response.status_code == 200
    body = response.json()
    assert body == {"success": False, "blocked": False, "message": "Username already taken", "reason": None}


def test_password_is_bcrypt_hash():
    client.post("/api/register", data={"username": "alice", "password": "secret"})
    db = TestingSessionLocal()
    user = db.query(User).filter(User.username == "alice").first()
    assert bcrypt.checkpw("secret".encode(), user.password.encode())


def test_login_success():
    client.post("/api/register", data={"username": "alice", "password": "secret"})
    response = client.post("/api/login", data={"username": "alice", "password": "secret"})
    assert response.status_code == 200
    body = response.json()
    assert body == {"success": True, "blocked": False, "message": "Login successful", "reason": None}


def test_login_wrong_password():
    client.post("/api/register", data={"username": "alice", "password": "secret"})
    response = client.post("/api/login", data={"username": "alice", "password": "wrong"})
    assert response.status_code == 200
    body = response.json()
    assert body == {"success": False, "blocked": False, "message": "Invalid credentials", "reason": None}


def test_threat_log_empty():
    response = client.get("/api/threat-log")
    assert response.status_code == 200
    assert response.json() == {"threats": []}
