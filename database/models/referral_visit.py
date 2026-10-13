from datetime import datetime, UTC
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from database.models import Base


class ReferralVisit(Base):
    __tablename__ = "referral_visit"

    __table_args__ = (
        UniqueConstraint("referrer_id", "visitor_id", name="unique_referrer_visitor"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    referrer_id: Mapped[int] = mapped_column(ForeignKey("user.id", ondelete="CASCADE"), nullable=False, index=True)
    visitor_id: Mapped[str] = mapped_column(String(64), nullable=False)

    converted_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"), nullable=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),
                                                 nullable=False, index=True)
