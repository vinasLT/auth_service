import enum
from datetime import datetime, UTC
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from database.models import Base


class RewardStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    CANCELLED = "cancelled"


class ReferralReward(Base):
    __tablename__ = "referral_reward"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    referrer_id: Mapped[int] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    referred_user_id: Mapped[int] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"), nullable=False,
                                                  index=True)

    external_purchase_id: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    lot_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    vin: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[RewardStatus] = mapped_column(Enum(RewardStatus, native_enum=False, length=32), nullable=False,
                                                 default=RewardStatus.PENDING, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),
                                                 nullable=False)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
