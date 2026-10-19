import pytest

from config import Environment, Settings
from services.referral.code import build_referral_link


@pytest.mark.asyncio
async def test_referral_base_url_follows_environment():
    assert Settings(ENVIRONMENT=Environment.DEVELOPMENT).REFERRAL_BASE_URL == "http://localhost:3000/?ref="
    assert Settings(ENVIRONMENT=Environment.PRODUCTION).REFERRAL_BASE_URL == "https://vinas.lt/?ref="


@pytest.mark.asyncio
async def test_build_referral_link_uses_environment_url(monkeypatch):
    monkeypatch.setattr("services.referral.code.settings.ENVIRONMENT", Environment.PRODUCTION)
    assert build_referral_link("4FSSKSMT") == "https://vinas.lt/?ref=4FSSKSMT"
