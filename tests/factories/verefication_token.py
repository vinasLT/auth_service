from datetime import datetime, UTC, timedelta

import factory
from factory.alchemy import SQLAlchemyModelFactory

from database.models.verification_code import VerificationCode, Destination


class VerificationCodeFactory(SQLAlchemyModelFactory):
    class Meta:
        model = VerificationCode
        sqlalchemy_session_persistence = "flush"

    uuid_key = factory.Faker("uuid4")
    user_id = factory.Faker("random_int", min=1, max=999999)

    code = factory.Faker("numerify", text="######")  # Генерирует 6-значный код
    destination = factory.Faker("random_element", elements=[dest.value for dest in Destination])

    is_verified = False

    # Код действителен в течение 10 минут по умолчанию
    created_at = factory.LazyFunction(lambda: datetime.now(UTC))
    expires_at = factory.LazyFunction(lambda: datetime.now(UTC) + timedelta(minutes=10))
    verified_at = None

