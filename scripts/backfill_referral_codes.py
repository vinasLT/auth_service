import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
PROJECT_ROOT = CURRENT_FILE.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session

from core.logger import logger
from database.db.session import engine
from database.models import User
from services.referral.code import generate_referral_code, MAX_GENERATION_ATTEMPTS


def _pick_unique_code(session: Session, taken_in_batch: set[str]) -> str:
    for _ in range(MAX_GENERATION_ATTEMPTS):
        code = generate_referral_code()
        if code in taken_in_batch:
            continue
        if session.scalar(select(User.id).where(User.referral_code == code)) is None:
            return code
    raise RuntimeError("Failed to generate a unique referral code")


def backfill_referral_codes(db_engine: Engine, batch_size: int = 500) -> int:
    total = 0
    while True:
        with Session(db_engine) as session, session.begin():
            user_ids = session.scalars(
                select(User.id).where(User.referral_code.is_(None)).order_by(User.id).limit(batch_size)
            ).all()
            if not user_ids:
                break

            taken_in_batch: set[str] = set()
            for user_id in user_ids:
                code = _pick_unique_code(session, taken_in_batch)
                taken_in_batch.add(code)
                session.execute(update(User).where(User.id == user_id).values(referral_code=code))

        total += len(user_ids)
        logger.info(f"Backfilled referral codes for {total} users")

    logger.info(f"Referral code backfill finished, users updated: {total}")
    return total


if __name__ == '__main__':
    backfill_referral_codes(engine)
