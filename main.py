from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI, APIRouter
from fastapi_limiter import FastAPILimiter

from config import settings
from core.logger import logger
from routers.v1.auth import auth_v1_router
from fastapi_problem.handler import add_exception_handler, new_exception_handler

from routers.v1.password_reset import password_reset_router
from routers.v1.verification_code import verification_code_router
from routers.v1.verify import verify_request_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    r = redis.asyncio.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(r, prefix="rl:")
    logger.info(f"{settings.APP_NAME} started!")
    yield
    await FastAPILimiter.close()

docs_url = "/docs" if settings.enable_docs else None
redoc_url = "/redoc"  if settings.enable_docs else None
openapi_url = "/openapi.json" if settings.enable_docs else None

app = FastAPI(
    title="Auth Service",
    description="JWT Authentication Service with AWS KMS",
    version="0.0.1",
    root_path=settings.ROOT_PATH,
    docs_url=docs_url,
    redoc_url=redoc_url,
    openapi_url=openapi_url,
    lifespan=lifespan
)


eh = new_exception_handler()
add_exception_handler(app, eh)

v1_router = APIRouter()
v1_router.include_router(auth_v1_router, tags=["auth"])
v1_router.include_router(verify_request_router, tags=["internal"])
v1_router.include_router(verification_code_router, prefix="/verification-code", tags=["verification-code"])
v1_router.include_router(password_reset_router, prefix="/password-reset", tags=["password-reset"])

app.include_router(v1_router, prefix="/v1")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": settings.APP_NAME}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, port=8000)