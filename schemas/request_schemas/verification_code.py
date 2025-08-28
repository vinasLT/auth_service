from pydantic import BaseModel, Field


class CodeIn(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, description="Verification code")