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


class BidPaidEvent(BaseEvent):
    bid_id: str = Field(..., min_length=1)
    lot_id: Optional[str] = None
    vin: Optional[str] = None
    payment_status: Optional[str] = None
