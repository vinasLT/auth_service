from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class BaseEvent(BaseModel):
    model_config = ConfigDict(coerce_numbers_to_str=True, extra="ignore")

    user_uuid: str = Field(..., min_length=1)


class BidPlacedEvent(BaseEvent):
    bid_id: Optional[str] = None
    lot_id: Optional[str] = None
    created_at: Optional[datetime] = None


class PurchaseCreatedEvent(BaseEvent):
    purchase_id: str = Field(..., min_length=1)
    lot_id: Optional[str] = None
    vin: Optional[str] = None
    created_at: Optional[datetime] = None


class PurchasePaidEvent(BaseEvent):
    purchase_id: str = Field(..., min_length=1)
    lot_id: Optional[str] = None
    vin: Optional[str] = None
    paid_at: Optional[datetime] = None


class PurchaseCancelledEvent(BaseEvent):
    purchase_id: str = Field(..., min_length=1)
    reason: Optional[str] = None
