from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ReferralVisitIn(BaseModel):
    referral_code: str = Field(..., min_length=1, max_length=32, json_schema_extra={"example": "AB2CD3EF"})


class ReferrerSortField(str, Enum):
    VISITS = "visits"
    REGISTRATIONS = "registrations"
    USERS_WITH_BIDS = "users_with_bids"
    PURCHASES_PAID = "purchases_paid"
    CREATED_AT = "created_at"


class SortOrder(str, Enum):
    ASC = "asc"
    DESC = "desc"


class ReferrerSearchIn(BaseModel):
    search: Optional[str] = Field('', description='Search by email, first, last names, phone number, referral code')
    only_active: bool = Field(True, description='Only users with referral activity (visits, referrals or wallet)')
    sort_by: ReferrerSortField = Field(ReferrerSortField.REGISTRATIONS)
    order: SortOrder = Field(SortOrder.DESC)
