from json import JSONDecodeError

from fastapi import Request

async def user_identifier(request: Request) -> str:
    try:
        body = await request.json()
    except JSONDecodeError:
        body = None
    if body and body.get('email'):
        return f"email:{body['email']}"
    ip = request.headers.get("X-Forwarded-For")
    if ip:
        ip = ip.split(",")[0].strip()
    else:
        ip = request.client.host
    return f"ip:{ip}"
