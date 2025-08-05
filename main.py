from contextlib import asynccontextmanager

import redis
from fastapi import FastAPI
from fastapi_limiter import FastAPILimiter

from config import settings
from routers.auth import auth_v1_router
from fastapi_problem.handler import add_exception_handler, new_exception_handler



@asynccontextmanager
async def lifespan(_: FastAPI):
    r = redis.asyncio.from_url(settings.REDIS_URL, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(r, prefix="rl:")
    yield
    await FastAPILimiter.close()


app = FastAPI(
    title="Auth Service",
    description="JWT Authentication Service with AWS KMS",
    version="1.0.0",
    lifespan=lifespan
)



eh = new_exception_handler()
add_exception_handler(app, eh)

app.include_router(auth_v1_router, prefix="/v1")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "auth-service"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, port=8000)