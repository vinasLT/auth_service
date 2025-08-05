from typing import Optional

from fastapi import Request

def client_ip_from_request(request: Request) -> Optional[str]:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[0]
    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip.strip()
    if request.client:
        return request.client.host
    return None

def device_name_from_user_agent(user_agent: str) -> str:
    ua = user_agent.lower()
    if "iphone" in ua or "ios" in ua:
        return "iPhone/iOS"
    if "ipad" in ua:
        return "iPad/iOS"
    if "android" in ua:
        return "Android"
    if "windows" in ua:
        return "Windows"
    if "mac os" in ua or "macintosh" in ua:
        return "macOS"
    if "linux" in ua:
        return "Linux"
    return "Unknown"