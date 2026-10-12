from datetime import datetime, UTC

from sqlalchemy import DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from database.models import Base


class ReferralWallet(Base):
    __tablename__ = "referral_wallet"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    user_id: Mapped[int] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"), nullable=False, unique=True,
                                         index=True)

    balance_cents: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_earned_cents: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_paid_out_cents: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),
                                                 nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),
                                                 onupdate=lambda: datetime.now(UTC), nullable=False)
