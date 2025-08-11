from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict

from database.models.singing_key import AlgorithmsEnum


class SingingKeyCreate(BaseModel):
    key_arn: str
    alg: AlgorithmsEnum
    is_active: Optional[bool] = True
    created_at: Optional[datetime] = None


class SingingKeyUpdate(BaseModel):
    key_arn: Optional[str] = None
    alg: Optional[AlgorithmsEnum] = None
    is_active: Optional[bool] = None
    created_at: Optional[datetime] = None


class SingingKeyRead(SingingKeyCreate):
    id: int
    created_at: datetime
    is_active: bool

    model_config = ConfigDict(from_attributes=True)