from typing import Any, Optional

from sqlalchemy import select, func, or_, Select, ScalarSelect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from database.models import User, Referral, ReferralVisit, ReferralReward
from database.models.referral_reward import RewardStatus
from schemas.request_schemas.referral import ReferrerSortField, SortOrder

ReferredUser = aliased(User, name="referred_user")
RewardReferrer = aliased(User, name="reward_referrer")
RewardReferredUser = aliased(User, name="reward_referred_user")


def _visits_count(referrer_id: Any) -> ScalarSelect:
    return (
        select(func.count(ReferralVisit.id))
        .where(ReferralVisit.referrer_id == referrer_id)
        .scalar_subquery()
    )


def _registrations_count(referrer_id: Any) -> ScalarSelect:
    return (
        select(func.count(Referral.id))
        .join(ReferredUser, ReferredUser.id == Referral.referred_user_id)
        .where(Referral.referrer_id == referrer_id, ReferredUser.email_verified.is_(True))
        .scalar_subquery()
    )


def _users_with_bids_count(referrer_id: Any) -> ScalarSelect:
    return (
        select(func.count(Referral.id))
        .where(Referral.referrer_id == referrer_id, Referral.first_bid_at.is_not(None))
        .scalar_subquery()
    )


def _rewards_count(referrer_id: Any, status: RewardStatus) -> ScalarSelect:
    return (
        select(func.count(ReferralReward.id))
        .where(ReferralReward.referrer_id == referrer_id, ReferralReward.status == status)
        .scalar_subquery()
    )


def _rewards_sum(referrer_id: Any, status: RewardStatus) -> ScalarSelect:
    return (
        select(func.coalesce(func.sum(ReferralReward.amount_cents), 0))
        .where(ReferralReward.referrer_id == referrer_id, ReferralReward.status == status)
        .scalar_subquery()
    )


def _referred_user_rewards_count(referrer_id: int, status: RewardStatus) -> ScalarSelect:
    return (
        select(func.count(ReferralReward.id))
        .where(
            ReferralReward.referrer_id == referrer_id,
            ReferralReward.referred_user_id == User.id,
            ReferralReward.status == status,
        )
        .scalar_subquery()
    )


class ReferralStatsService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_user_stats(self, user_id: int) -> dict[str, int]:
        stmt = select(
            _visits_count(user_id).label("visits"),
            _registrations_count(user_id).label("registrations"),
            _users_with_bids_count(user_id).label("users_with_bids"),
            _rewards_count(user_id, RewardStatus.PENDING).label("purchases_pending"),
            _rewards_count(user_id, RewardStatus.APPROVED).label("purchases_paid"),
            _rewards_sum(user_id, RewardStatus.PENDING).label("pending_cents"),
        )
        row = (await self.session.execute(stmt)).one()
        return dict(row._mapping)

    async def get_global_stats(self) -> dict[str, int]:
        registrations = (
            select(func.count(Referral.id))
            .join(ReferredUser, ReferredUser.id == Referral.referred_user_id)
            .where(ReferredUser.email_verified.is_(True))
            .scalar_subquery()
        )

        def rewards_count(status: RewardStatus) -> ScalarSelect:
            return select(func.count(ReferralReward.id)).where(ReferralReward.status == status).scalar_subquery()

        def rewards_sum(status: RewardStatus) -> ScalarSelect:
            return (
                select(func.coalesce(func.sum(ReferralReward.amount_cents), 0))
                .where(ReferralReward.status == status)
                .scalar_subquery()
            )

        stmt = select(
            select(func.count(ReferralVisit.id)).scalar_subquery().label("total_visits"),
            registrations.label("total_registrations"),
            select(func.count(Referral.id)).where(Referral.first_bid_at.is_not(None))
            .scalar_subquery().label("total_users_with_bids"),
            rewards_count(RewardStatus.PENDING).label("rewards_pending_count"),
            rewards_sum(RewardStatus.PENDING).label("rewards_pending_cents"),
            rewards_count(RewardStatus.APPROVED).label("rewards_approved_count"),
            rewards_sum(RewardStatus.APPROVED).label("rewards_approved_cents"),
        )
        row = (await self.session.execute(stmt)).one()
        return dict(row._mapping)

    def get_referrers_stmt(
            self,
            search: str = '',
            only_active: bool = True,
            sort_by: ReferrerSortField = ReferrerSortField.REGISTRATIONS,
            order: SortOrder = SortOrder.DESC,
    ) -> Select:
        columns = {
            ReferrerSortField.VISITS: _visits_count(User.id).label("visits"),
            ReferrerSortField.REGISTRATIONS: _registrations_count(User.id).label("registrations"),
            ReferrerSortField.USERS_WITH_BIDS: _users_with_bids_count(User.id).label("users_with_bids"),
            ReferrerSortField.PURCHASES_PAID: _rewards_count(User.id, RewardStatus.APPROVED).label("purchases_paid"),
            ReferrerSortField.CREATED_AT: User.created_at,
        }

        stmt = (
            select(
                User.uuid_key.label("user_uuid"),
                User.email,
                User.first_name,
                User.last_name,
                User.referral_code,
                columns[ReferrerSortField.VISITS],
                columns[ReferrerSortField.REGISTRATIONS],
                columns[ReferrerSortField.USERS_WITH_BIDS],
                _rewards_count(User.id, RewardStatus.PENDING).label("purchases_pending"),
                columns[ReferrerSortField.PURCHASES_PAID],
            )
        )

        if only_active:
            stmt = stmt.where(or_(
                select(ReferralVisit.id).where(ReferralVisit.referrer_id == User.id).exists(),
                select(Referral.id).where(Referral.referrer_id == User.id).exists(),
            ))

        if search and search.strip():
            term = f"%{search.strip().lower()}%"
            stmt = stmt.where(or_(
                func.lower(User.email).like(term),
                func.lower(User.first_name).like(term),
                func.lower(User.last_name).like(term),
                func.lower(User.phone_number).like(term),
                func.lower(User.referral_code).like(term),
                func.lower(func.concat(User.first_name, ' ', User.last_name)).like(term),
            ))

        sort_column = columns[sort_by]
        sort_expr = sort_column.asc() if order == SortOrder.ASC else sort_column.desc()
        return stmt.order_by(sort_expr, User.id.desc())

    def get_referred_users_stmt(self, referrer_id: int, only_verified: bool) -> Select:
        stmt = (
            select(
                User.uuid_key.label("user_uuid"),
                User.email,
                User.first_name,
                User.last_name,
                User.email_verified,
                Referral.created_at.label("registered_at"),
                Referral.bids_count,
                Referral.first_bid_at,
                _referred_user_rewards_count(referrer_id, RewardStatus.APPROVED).label("purchases_paid"),
                _referred_user_rewards_count(referrer_id, RewardStatus.PENDING).label("purchases_pending"),
            )
            .join(Referral, Referral.referred_user_id == User.id)
            .where(Referral.referrer_id == referrer_id)
        )
        if only_verified:
            stmt = stmt.where(User.email_verified.is_(True))
        return stmt.order_by(Referral.created_at.desc(), Referral.id.desc())

    def get_rewards_stmt(self, referrer_id: int, status: Optional[RewardStatus] = None) -> Select:
        stmt = select(ReferralReward).where(ReferralReward.referrer_id == referrer_id)
        if status is not None:
            stmt = stmt.where(ReferralReward.status == status)
        return stmt.order_by(ReferralReward.created_at.desc(), ReferralReward.id.desc())

    def get_admin_rewards_stmt(self, referrer_id: Optional[int] = None,
                               status: Optional[RewardStatus] = None) -> Select:
        stmt = (
            select(
                ReferralReward,
                RewardReferrer.uuid_key.label("referrer_uuid"),
                RewardReferrer.email.label("referrer_email"),
                RewardReferredUser.uuid_key.label("referred_user_uuid"),
                RewardReferredUser.email.label("referred_user_email"),
            )
            .join(RewardReferrer, RewardReferrer.id == ReferralReward.referrer_id)
            .join(RewardReferredUser, RewardReferredUser.id == ReferralReward.referred_user_id)
        )
        if referrer_id is not None:
            stmt = stmt.where(ReferralReward.referrer_id == referrer_id)
        if status is not None:
            stmt = stmt.where(ReferralReward.status == status)
        return stmt.order_by(ReferralReward.created_at.desc(), ReferralReward.id.desc())
