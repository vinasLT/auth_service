from datetime import datetime, UTC

from sqlalchemy import ForeignKey, DateTime, String, Text
from sqlalchemy.orm import mapped_column, Mapped, relationship

from database.models import Base


class RefreshToken(Base):
    __tablename__ = 'refresh_token'

    id: Mapped[int] = mapped_column(primary_key=True, index=True, autoincrement=True)

    jti: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)

    user_id: Mapped[int] = mapped_column(ForeignKey('user.id', ondelete='CASCADE'), nullable=False)

    token_family: Mapped[str] = mapped_column(String, nullable=False, index=True)

    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )

    device_name: Mapped[str] = mapped_column(String, nullable=True)
    user_agent: Mapped[str] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str] = mapped_column(String, nullable=True)

    is_active: Mapped[bool] = mapped_column(default=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)

    replaced_by_id: Mapped[int] = mapped_column(
        ForeignKey('refresh_token.id', ondelete='CASCADE'),
        nullable=True
    )

    # Define the relationship separately
    replaced_by: Mapped["RefreshToken"] = relationship(
        "RefreshToken",
        remote_side=[id],
        back_populates="replaces"
    )
    
    replaces: Mapped["RefreshToken"] = relationship(
        "RefreshToken",
        remote_side=[replaced_by_id],
        back_populates="replaced_by"
    )