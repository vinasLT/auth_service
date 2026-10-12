import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database.models import User

REFERRAL_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
REFERRAL_CODE_LENGTH = 8
MAX_GENERATION_ATTEMPTS = 10


def generate_referral_code() -> str:
    return "".join(secrets.choice(REFERRAL_CODE_ALPHABET) for _ in range(REFERRAL_CODE_LENGTH))


def normalize_referral_code(code: str | None) -> str | None:
    if not code:
        return None
    normalized = code.strip().upper()
    return normalized or None


def build_referral_link(code: str | None) -> str | None:
    if not code:
        return None
    return f"{settings.REFERRAL_BASE_URL}{code}"


async def generate_unique_referral_code(session: AsyncSession) -> str:
    for _ in range(MAX_GENERATION_ATTEMPTS):
        code = generate_referral_code()
        exists = await session.scalar(select(User.id).where(User.referral_code == code))
        if not exists:
            return code
    raise RuntimeError("Failed to generate a unique referral code")
