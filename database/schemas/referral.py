from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict


class ReferralVisitCreate(BaseModel):
    referrer_id: int
    visitor_id: str


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


class ReferralRewardUpdate(BaseModel):
    pass


class ReferralRewardRead(BaseModel):
    id: int
    external_purchase_id: str
    lot_id: Optional[str]
    vin: Optional[str]
    amount_cents: int
    currency: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
