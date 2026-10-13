from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict

from database.models.referral_reward import RewardStatus


class ReferralVisitCreate(BaseModel):
    referrer_id: int
    visitor_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    landing_url: Optional[str] = None


class ReferralVisitUpdate(BaseModel):
    converted_user_id: Optional[int] = None


class ReferralCreate(BaseModel):
    referrer_id: int
    referred_user_id: int
    visit_id: Optional[int] = None


class ReferralUpdate(BaseModel):
    first_bid_at: Optional[datetime] = None
    bids_count: Optional[int] = None


class ReferralRewardCreate(BaseModel):
    referrer_id: int
    referred_user_id: int
    external_purchase_id: str
    lot_id: Optional[str] = None
    vin: Optional[str] = None
    amount_cents: int
    currency: str
    status: RewardStatus = RewardStatus.PENDING
    cancelled_at: Optional[datetime] = None


class ReferralRewardUpdate(BaseModel):
    status: Optional[RewardStatus] = None
    approved_at: Optional[datetime] = None
    cancelled_at: Optional[datetime] = None


class ReferralRewardRead(BaseModel):
    id: int
    external_purchase_id: str
    lot_id: Optional[str]
    vin: Optional[str]
    amount_cents: int
    currency: str
    status: RewardStatus
    created_at: datetime
    approved_at: Optional[datetime]
    cancelled_at: Optional[datetime]

    model_config = ConfigDict(from_attributes=True)
