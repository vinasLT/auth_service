import enum
from datetime import datetime, UTC
from typing import Optional

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from database.models import Base


class WalletTransactionType(str, enum.Enum):
    REWARD_CREDIT = "reward_credit"
    REWARD_REVERSAL = "reward_reversal"
    PAYOUT = "payout"
    ADJUSTMENT = "adjustment"


class WalletTransaction(Base):
    __tablename__ = "wallet_transaction"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    wallet_id: Mapped[int] = mapped_column(ForeignKey("referral_wallet.id", ondelete="CASCADE"), nullable=False,
                                           index=True)
    type: Mapped[WalletTransactionType] = mapped_column(Enum(WalletTransactionType, native_enum=False, length=32),
                                                        nullable=False, index=True)

    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    balance_after_cents: Mapped[int] = mapped_column(Integer, nullable=False)

    reward_id: Mapped[Optional[int]] = mapped_column(ForeignKey("referral_reward.id", ondelete="SET NULL"),
                                                     nullable=True, index=True)
    created_by_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("user.id", ondelete="SET NULL"),
                                                              nullable=True)

    external_reference: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC),
                                                 nullable=False, index=True)
