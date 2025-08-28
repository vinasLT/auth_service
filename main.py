from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI, APIRouter
from fastapi_limiter import FastAPILimiter
from fastapi_pagination import add_pagination

from config import settings
from core.logger import logger
from routers.v1.private.role import roles_router
from routers.v1.private.user import user_router, user_control_router
from routers.v1.public.auth import auth_v1_router
from fastapi_problem.handler import add_exception_handler, new_exception_handler

from routers.v1.public.password_reset import password_reset_router
from routers.v1.public.verification_code import verification_code_router
from routers.v1.public.verify import verify_request_router


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

add_pagination(app)

v1_router = APIRouter(prefix="/v1")

v1_router.include_router(auth_v1_router, tags=["auth"])
v1_router.include_router(verify_request_router, tags=["internal"])
v1_router.include_router(verification_code_router, prefix="/verification-code", tags=["verification-code"])
v1_router.include_router(password_reset_router, prefix="/password-reset", tags=["password-reset"])

private_router = APIRouter(prefix="/private")
private_router.include_router(user_control_router, tags=["user"])
private_router.include_router(roles_router, tags=["roles"])

v1_router.include_router(private_router)

app.include_router(v1_router)




@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": settings.APP_NAME}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, port=8000)