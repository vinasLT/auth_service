from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict

from database.schemas.referral import ReferralRewardRead, WalletTransactionRead


class ReferralVisitOut(BaseModel):
    valid: bool
    visit_id: Optional[int] = None


class ReferralStatsOut(BaseModel):
    visits: int = 0
    registrations: int = 0
    users_with_bids: int = 0
    purchases_pending: int = 0
    purchases_paid: int = 0


class WalletOut(BaseModel):
    balance_cents: int = 0
    pending_cents: int = 0
    total_earned_cents: int = 0
    total_paid_out_cents: int = 0
    currency: str


class MyReferralOut(BaseModel):
    referral_code: str
    referral_link: str
    stats: ReferralStatsOut
    wallet: WalletOut


class ReferredUserOut(BaseModel):
    first_name: str
    last_name: str
    email: str
    registered_at: datetime
    has_bid: bool
    first_bid_at: Optional[datetime] = None
    purchases_paid: int = 0
    purchases_pending: int = 0


class RewardOut(ReferralRewardRead):
    pass


class WalletTransactionOut(WalletTransactionRead):
    pass


class AdminReferralStatsOut(BaseModel):
    total_visits: int = 0
    total_registrations: int = 0
    total_users_with_bids: int = 0
    rewards_pending_count: int = 0
    rewards_pending_cents: int = 0
    rewards_approved_count: int = 0
    rewards_approved_cents: int = 0
    total_wallet_balance_cents: int = 0
    total_paid_out_cents: int = 0
    currency: str


class ReferrerOut(BaseModel):
    user_uuid: str
    email: str
    first_name: str
    last_name: str
    referral_code: Optional[str] = None
    visits: int = 0
    registrations: int = 0
    users_with_bids: int = 0
    purchases_pending: int = 0
    purchases_paid: int = 0
    balance_cents: int = 0
    total_earned_cents: int = 0
    total_paid_out_cents: int = 0


class AdminReferralUserOut(BaseModel):
    user_uuid: str
    email: str
    first_name: str
    last_name: str
    referral_code: Optional[str] = None
    referral_link: Optional[str] = None
    referred_by_uuid: Optional[str] = None
    stats: ReferralStatsOut
    wallet: WalletOut


class AdminReferredUserOut(BaseModel):
    user_uuid: str
    email: str
    first_name: str
    last_name: str
    email_verified: bool
    registered_at: datetime
    bids_count: int = 0
    first_bid_at: Optional[datetime] = None
    purchases_paid: int = 0
    purchases_pending: int = 0


class AdminRewardOut(ReferralRewardRead):
    referrer_uuid: str
    referrer_email: str
    referred_user_uuid: str
    referred_user_email: str


class AdminWalletTransactionOut(WalletTransactionRead):
    created_by_user_id: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)
