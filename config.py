from enum import Enum

from pydantic_settings import BaseSettings

from dotenv import load_dotenv

load_dotenv()


class Environment(str, Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"

class Settings(BaseSettings):
    # Database

    DB_HOST: str = "localhost"
    DB_PORT: str = "5432"
    DB_NAME: str = "test_db"
    DB_USER: str = "postgres"
    DB_PASSWORD: str = "testpass"


    # Redis
    REDIS_URL: str = "redis://localhost:6379"

    # AWS
    AWS_REGION: str = "eu-north-1"
    AWS_ACCESS_KEY_ID: str = 'test-key'
    AWS_SECRET_ACCESS_KEY: str = 'test-key'
    AWS_KMS_KEY_ARN: str = 'arn:aws:kms:eu-north-1:533266961080:key/71dc53ed-5b1d-43fe-b8ca-5a4ba731cc90'

    # Security
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Application
    APP_NAME: str = "auth-service"
    AUDIENCE: str = "web-api"
    DEBUG: bool = True
    ROOT_PATH: str = ''
    ENVIRONMENT: Environment = Environment.DEVELOPMENT

    @property
    def enable_docs(self) -> bool:
        return self.ENVIRONMENT in [Environment.DEVELOPMENT]


    # RabbitMQ
    RABBITMQ_URL: str = "amqp://guest:guest@localhost/"
    RABBITMQ_EXCHANGE_NAME: str = 'events'


    class Config:
        env_file = ".env"


settings = Settings()