from typing import Optional, Sequence

from fastapi import APIRouter, Body, Depends, Path, Query
from fastapi_pagination.ext.sqlalchemy import paginate
from rfc9457 import NotFoundProblem
from sqlalchemy.ext.asyncio import AsyncSession

from config import Permissions, settings
from database.crud.referral_stats import ReferralStatsService
from database.crud.referral_wallet import ReferralWalletService
from database.crud.user import UserService
from database.crud.wallet_transaction import WalletTransactionService
from database.db.session import get_async_db
from database.models import User
from database.schemas.referral import ReferralRewardRead
from dependencies.security import JWTUser, require_all_permissions
from schemas.request_schemas.referral import (
    PayoutIn,
    AdjustmentIn,
    RewardActionIn,
    RewardFilterIn,
    ReferrerSearchIn,
)
from schemas.response_schemas.referral import (
    MyReferralOut,
    ReferralStatsOut,
    WalletOut,
    ReferredUserOut,
    RewardOut,
    WalletTransactionOut,
    AdminReferralStatsOut,
    ReferrerOut,
    AdminReferralUserOut,
    AdminReferredUserOut,
    AdminRewardOut,
    AdminWalletTransactionOut,
)
from services.referral.code import build_referral_link
from services.referral.referral_service import ReferralService
from services.referral.wallet_service import WalletService
from utils.masking import mask_email, mask_last_name
from utils.pagination_page import create_pagination_page

referral_router = APIRouter(prefix="/referral")

ReferredUserPage = create_pagination_page(ReferredUserOut)
RewardPage = create_pagination_page(RewardOut)
WalletTransactionPage = create_pagination_page(WalletTransactionOut)
ReferrerPage = create_pagination_page(ReferrerOut)
AdminReferredUserPage = create_pagination_page(AdminReferredUserOut)
AdminRewardPage = create_pagination_page(AdminRewardOut)
AdminWalletTransactionPage = create_pagination_page(AdminWalletTransactionOut)


async def _get_user_or_404(user_service: UserService, user_uuid: str) -> User:
    user = await user_service.get_user_by_uuid(user_uuid)
    if not user:
        raise NotFoundProblem(detail="User not found")
    return user


async def _get_admin(user_service: UserService, admin: JWTUser) -> User:
    return await _get_user_or_404(user_service, admin.id)


async def _build_stats_and_wallet(db: AsyncSession, user_id: int) -> tuple[ReferralStatsOut, WalletOut]:
    stats = await ReferralStatsService(db).get_user_stats(user_id)
    wallet = await ReferralWalletService(db).get_by_user_id(user_id)
    wallet_out = WalletOut(
        balance_cents=wallet.balance_cents if wallet else 0,
        pending_cents=stats["pending_cents"],
        total_earned_cents=wallet.total_earned_cents if wallet else 0,
        total_paid_out_cents=wallet.total_paid_out_cents if wallet else 0,
        currency=settings.REFERRAL_CURRENCY,
    )
    return ReferralStatsOut(**stats), wallet_out


def _rows_to_dicts(rows: Sequence) -> list[dict]:
    return [dict(row._mapping) for row in rows]


def _mask_referred_users(rows: Sequence) -> list[ReferredUserOut]:
    return [
        ReferredUserOut(
            first_name=row.first_name,
            last_name=mask_last_name(row.last_name),
            email=mask_email(row.email),
            registered_at=row.registered_at,
            has_bid=row.first_bid_at is not None,
            first_bid_at=row.first_bid_at,
            purchases_paid=row.purchases_paid,
            purchases_pending=row.purchases_pending,
        )
        for row in rows
    ]


def _admin_rewards(rows: Sequence) -> list[AdminRewardOut]:
    return [
        AdminRewardOut(
            **ReferralRewardRead.model_validate(row[0]).model_dump(),
            referrer_uuid=row.referrer_uuid,
            referrer_email=row.referrer_email,
            referred_user_uuid=row.referred_user_uuid,
            referred_user_email=row.referred_user_email,
        )
        for row in rows
    ]


# ---------- Current user ----------

@referral_router.get("/me", response_model=MyReferralOut, description="Referral link, stats and wallet of current user")
async def get_my_referral(
        current_user: JWTUser = Depends(require_all_permissions(Permissions.REFERRAL_READ_OWN)),
        db: AsyncSession = Depends(get_async_db),
) -> MyReferralOut:
    user = await _get_user_or_404(UserService(db), current_user.id)
    user = await ReferralService(db).ensure_code(user)
    stats, wallet = await _build_stats_and_wallet(db, user.id)
    return MyReferralOut(
        referral_code=user.referral_code,
        referral_link=build_referral_link(user.referral_code),
        stats=stats,
        wallet=wallet,
    )


@referral_router.get("/me/referrals", response_model=ReferredUserPage, description="Users registered via my link")
async def get_my_referrals(
        current_user: JWTUser = Depends(require_all_permissions(Permissions.REFERRAL_READ_OWN)),
        db: AsyncSession = Depends(get_async_db),
):
    user = await _get_user_or_404(UserService(db), current_user.id)
    stmt = ReferralStatsService(db).get_referred_users_stmt(user.id, only_verified=True)
    return await paginate(db, stmt, transformer=_mask_referred_users, unique=False)


@referral_router.get("/me/rewards", response_model=RewardPage, description="My referral rewards")
async def get_my_rewards(
        data: RewardFilterIn = Query(...),
        current_user: JWTUser = Depends(require_all_permissions(Permissions.REFERRAL_READ_OWN)),
        db: AsyncSession = Depends(get_async_db),
):
    user = await _get_user_or_404(UserService(db), current_user.id)
    return await paginate(db, ReferralStatsService(db).get_rewards_stmt(user.id, data.status))


@referral_router.get("/me/transactions", response_model=WalletTransactionPage,
                     description="My referral wallet history")
async def get_my_transactions(
        current_user: JWTUser = Depends(require_all_permissions(Permissions.REFERRAL_READ_OWN)),
        db: AsyncSession = Depends(get_async_db),
):
    user = await _get_user_or_404(UserService(db), current_user.id)
    return await paginate(db, WalletTransactionService(db).get_user_transactions_stmt(user.id))


# ---------- Admin ----------

@referral_router.get("/admin/stats", response_model=AdminReferralStatsOut, description="Global referral stats",
                     dependencies=[Depends(require_all_permissions(Permissions.REFERRAL_READ_ALL))])
async def get_admin_stats(db: AsyncSession = Depends(get_async_db)) -> AdminReferralStatsOut:
    stats = await ReferralStatsService(db).get_global_stats()
    return AdminReferralStatsOut(**stats, currency=settings.REFERRAL_CURRENCY)


@referral_router.get("/admin/referrers", response_model=ReferrerPage, description="Referrers with their stats",
                     dependencies=[Depends(require_all_permissions(Permissions.REFERRAL_READ_ALL))])
async def get_admin_referrers(data: ReferrerSearchIn = Query(...), db: AsyncSession = Depends(get_async_db)):
    stmt = ReferralStatsService(db).get_referrers_stmt(
        search=data.search or '',
        only_active=data.only_active,
        sort_by=data.sort_by,
        order=data.order,
    )
    return await paginate(db, stmt, transformer=_rows_to_dicts, unique=False)


@referral_router.get("/admin/rewards", response_model=AdminRewardPage, description="Rewards of all users",
                     dependencies=[Depends(require_all_permissions(Permissions.REFERRAL_READ_ALL))])
async def get_admin_rewards(data: RewardFilterIn = Query(...), db: AsyncSession = Depends(get_async_db)):
    stmt = ReferralStatsService(db).get_admin_rewards_stmt(status=data.status)
    return await paginate(db, stmt, transformer=_admin_rewards, unique=False)


@referral_router.post("/admin/rewards/{reward_id}/approve", response_model=RewardOut,
                      description="Approve reward manually and credit referrer wallet")
async def approve_reward(
        reward_id: int = Path(...),
        data: Optional[RewardActionIn] = Body(None),
        admin: JWTUser = Depends(require_all_permissions(Permissions.REFERRAL_WRITE_ALL)),
        db: AsyncSession = Depends(get_async_db),
):
    admin_user = await _get_admin(UserService(db), admin)
    return await WalletService(db).approve_reward(reward_id, admin_id=admin_user.id,
                                                  note=data.note if data else None)


@referral_router.post("/admin/rewards/{reward_id}/cancel", response_model=RewardOut,
                      description="Cancel reward manually; approved rewards are reversed from the wallet")
async def cancel_reward(
        reward_id: int = Path(...),
        data: Optional[RewardActionIn] = Body(None),
        admin: JWTUser = Depends(require_all_permissions(Permissions.REFERRAL_WRITE_ALL)),
        db: AsyncSession = Depends(get_async_db),
):
    admin_user = await _get_admin(UserService(db), admin)
    return await WalletService(db).cancel_reward(reward_id, admin_id=admin_user.id,
                                                 note=data.note if data else None)


@referral_router.get("/admin/users/{user_uuid}", response_model=AdminReferralUserOut,
                     description="Referral stats and wallet of a user",
                     dependencies=[Depends(require_all_permissions(Permissions.REFERRAL_READ_ALL))])
async def get_admin_user_referral(
        user_uuid: str = Path(...),
        db: AsyncSession = Depends(get_async_db),
) -> AdminReferralUserOut:
    user_service = UserService(db)
    user = await _get_user_or_404(user_service, user_uuid)
    referred_by = await user_service.get(user.referred_by_id) if user.referred_by_id else None
    stats, wallet = await _build_stats_and_wallet(db, user.id)
    return AdminReferralUserOut(
        user_uuid=user.uuid_key,
        email=user.email,
        first_name=user.first_name,
        last_name=user.last_name,
        referral_code=user.referral_code,
        referral_link=build_referral_link(user.referral_code),
        referred_by_uuid=referred_by.uuid_key if referred_by else None,
        stats=stats,
        wallet=wallet,
    )


@referral_router.get("/admin/users/{user_uuid}/referrals", response_model=AdminReferredUserPage,
                     description="Users referred by a user, including unverified",
                     dependencies=[Depends(require_all_permissions(Permissions.REFERRAL_READ_ALL))])
async def get_admin_user_referrals(user_uuid: str = Path(...), db: AsyncSession = Depends(get_async_db)):
    user = await _get_user_or_404(UserService(db), user_uuid)
    stmt = ReferralStatsService(db).get_referred_users_stmt(user.id, only_verified=False)
    return await paginate(db, stmt, transformer=_rows_to_dicts, unique=False)


@referral_router.get("/admin/users/{user_uuid}/rewards", response_model=AdminRewardPage,
                     description="Rewards of a user",
                     dependencies=[Depends(require_all_permissions(Permissions.REFERRAL_READ_ALL))])
async def get_admin_user_rewards(
        user_uuid: str = Path(...),
        data: RewardFilterIn = Query(...),
        db: AsyncSession = Depends(get_async_db),
):
    user = await _get_user_or_404(UserService(db), user_uuid)
    stmt = ReferralStatsService(db).get_admin_rewards_stmt(referrer_id=user.id, status=data.status)
    return await paginate(db, stmt, transformer=_admin_rewards, unique=False)


@referral_router.get("/admin/users/{user_uuid}/transactions", response_model=AdminWalletTransactionPage,
                     description="Wallet history of a user",
                     dependencies=[Depends(require_all_permissions(Permissions.REFERRAL_READ_ALL))])
async def get_admin_user_transactions(user_uuid: str = Path(...), db: AsyncSession = Depends(get_async_db)):
    user = await _get_user_or_404(UserService(db), user_uuid)
    return await paginate(db, WalletTransactionService(db).get_user_transactions_stmt(user.id))


@referral_router.post("/admin/users/{user_uuid}/payouts", response_model=AdminWalletTransactionOut,
                      status_code=201, description="Register manual payout and deduct it from the wallet")
async def create_payout(
        user_uuid: str = Path(...),
        data: PayoutIn = Body(...),
        admin: JWTUser = Depends(require_all_permissions(Permissions.REFERRAL_WRITE_ALL)),
        db: AsyncSession = Depends(get_async_db),
):
    user_service = UserService(db)
    user = await _get_user_or_404(user_service, user_uuid)
    admin_user = await _get_admin(user_service, admin)
    return await WalletService(db).payout(
        user_id=user.id,
        amount_cents=data.amount_cents,
        admin_id=admin_user.id,
        note=data.note,
        external_reference=data.external_reference,
    )


@referral_router.post("/admin/users/{user_uuid}/adjustments", response_model=AdminWalletTransactionOut,
                      status_code=201, description="Manual wallet correction (positive or negative)")
async def create_adjustment(
        user_uuid: str = Path(...),
        data: AdjustmentIn = Body(...),
        admin: JWTUser = Depends(require_all_permissions(Permissions.REFERRAL_WRITE_ALL)),
        db: AsyncSession = Depends(get_async_db),
):
    user_service = UserService(db)
    user = await _get_user_or_404(user_service, user_uuid)
    admin_user = await _get_admin(user_service, admin)
    return await WalletService(db).adjust(
        user_id=user.id,
        amount_cents=data.amount_cents,
        admin_id=admin_user.id,
        note=data.note,
    )
