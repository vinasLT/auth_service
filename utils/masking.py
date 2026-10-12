def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return f"{local[:1]}***"
    visible = local[:2] if len(local) > 2 else local[:1]
    return f"{visible}***@{domain}"


def mask_last_name(last_name: str) -> str:
    return f"{last_name[:1]}." if last_name else ""
