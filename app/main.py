from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.database import Base, engine
from app.routes import router


app = FastAPI()
app.include_router(router)

BASE_DIR = Path(__file__).resolve().parent.parent
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "frontend")), name="static")


@app.on_event("startup")
def create_tables() -> None:
	Base.metadata.create_all(bind=engine)
	engine.dispose()
