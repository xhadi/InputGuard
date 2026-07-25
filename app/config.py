from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SECURITY_ENABLED: bool = True
    DATABASE_URL: str = "sqlite:///./inputguard.db"
    LOG_FILE: str = "threats.log"

    class Config:
        env_file = ".env"


settings = Settings()
