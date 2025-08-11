from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI
from fastapi_limiter import FastAPILimiter

from config import settings
from core.logger import logger
from routers.v1.auth import auth_v1_router
from fastapi_problem.handler import add_exception_handler, new_exception_handler

from routers.v1.verification_code import verification_code_router
from routers.v1.verify import verify_request_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    r = redis.asyncio.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(r, prefix="rl:")
    logger.info(f"{settings.APP_NAME} started!")
    yield
    await FastAPILimiter.close()


app = FastAPI(
    title="Auth Service",
    description="JWT Authentication Service with AWS KMS",
    version="0.0.1",
    lifespan=lifespan
)


eh = new_exception_handler()
add_exception_handler(app, eh)

app.include_router(auth_v1_router, prefix="/v1", tags=["auth"])
app.include_router(verify_request_router, prefix="/v1", tags=["internal"])

app.include_router(verification_code_router, prefix="/v1/verification-code", tags=["verification-code"])


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": settings.APP_NAME}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, port=8000)