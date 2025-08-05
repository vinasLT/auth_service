from pydantic_settings import BaseSettings

from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql+asyncpg://authuser:authpass@postgres:5432/authdb"
    SYNC_DATABASE_URL: str = "postgresql://authuser:authpass@postgres:5432/authdb"

    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # AWS
    AWS_REGION: str = "eu-north-1"
    AWS_ACCESS_KEY_ID: str
    AWS_SECRET_ACCESS_KEY: str
    AWS_KMS_KEY_ARN: str = 'arn:aws:kms:eu-north-1:533266961080:key/71dc53ed-5b1d-43fe-b8ca-5a4ba731cc90'

    # Security
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Application
    APP_NAME: str = "Auth Service"
    DEBUG: bool = True

    class Config:
        env_file = ".env"


settings = Settings()