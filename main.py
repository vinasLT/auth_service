from fastapi import FastAPI

from utils.app_factory import create_app

app: FastAPI = create_app()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=8003)