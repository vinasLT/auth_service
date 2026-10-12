from datetime import datetime, UTC
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column

from database.models import Base


class Referral(Base):
    __tablename__ = "referral"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    referrer_id: Mapped[int] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    referred_user_id: Mapped[int] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    visit_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("referral_visit.id", ondelete="SET NULL"), nullable=True
    )

    first_bid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    bids_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),
                                                 nullable=False)
