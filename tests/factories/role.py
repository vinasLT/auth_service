import factory
from factory.alchemy import SQLAlchemyModelFactory

from database.models import Role
from tests.factories.token_session_user_factories import fake


class RoleFactory(SQLAlchemyModelFactory):
    class Meta:
        model = Role
        sqlalchemy_session_persistence = "flush"

    name = factory.Sequence(lambda n: f"role_{n}")

    is_default = False

    description = factory.LazyAttribute(lambda obj: fake.text(max_nb_chars=100))





