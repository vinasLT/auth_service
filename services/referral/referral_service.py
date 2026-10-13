from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from core.logger import logger
from database.crud.referral import ReferralRecordService
from database.crud.referral_visit import ReferralVisitService
from database.crud.user import UserService
from database.models import User, Referral, ReferralVisit
from database.schemas.referral import ReferralVisitCreate
from services.referral.code import normalize_referral_code, generate_unique_referral_code


class ReferralService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.user_service = UserService(session)
        self.referral_record_service = ReferralRecordService(session)
        self.visit_service = ReferralVisitService(session)

    async def get_active_referrer(self, referral_code: Optional[str]) -> Optional[User]:
        code = normalize_referral_code(referral_code)
        if not code:
            return None
        referrer = await self.user_service.get_by_referral_code(code)
        if not referrer or not referrer.is_active:
            return None
        return referrer

    async def ensure_code(self, user: User) -> User:
        if user.referral_code:
            return user
        user.referral_code = await generate_unique_referral_code(self.session)
        await self.session.commit()
        await self.session.refresh(user)
        return user

    async def attach_referrer(
            self,
            user: User,
            referral_code: Optional[str],
            visit_id: Optional[int] = None,
    ) -> Optional[Referral]:
        """Links the user to a referrer without committing; invalid input is ignored."""
        if not referral_code or user.referred_by_id is not None:
            return None

        referrer = await self.get_active_referrer(referral_code)
        if not referrer or referrer.id == user.id:
            logger.info("Referral attribution skipped", extra={"user_id": user.id, "referral_code": referral_code})
            return None

        if await self.referral_record_service.get_by_referred_user_id(user.id):
            return None

        visit: Optional[ReferralVisit] = None
        if visit_id is not None:
            visit = await self.visit_service.get(visit_id)
            if visit and visit.referrer_id == referrer.id and visit.converted_user_id is None:
                visit.converted_user_id = user.id
            else:
                visit = None

        user.referred_by_id = referrer.id
        referral = Referral(
            referrer_id=referrer.id,
            referred_user_id=user.id,
            visit_id=visit.id if visit else None,
        )
        self.session.add(referral)
        await self.session.flush()

        logger.info("Referral attributed", extra={
            "user_id": user.id,
            "referrer_id": referrer.id,
            "visit_id": referral.visit_id,
        })
        return referral

    async def track_visit(self, referral_code: str, visitor_id: str) -> Optional[ReferralVisit]:
        referrer = await self.get_active_referrer(referral_code)
        if not referrer:
            return None

        existing = await self.visit_service.get_by_referrer_and_visitor(referrer.id, visitor_id)
        if existing:
            return existing

        try:
            return await self.visit_service.create(ReferralVisitCreate(
                referrer_id=referrer.id,
                visitor_id=visitor_id,
            ))
        except IntegrityError:
            await self.session.rollback()
            return await self.visit_service.get_by_referrer_and_visitor(referrer.id, visitor_id)
