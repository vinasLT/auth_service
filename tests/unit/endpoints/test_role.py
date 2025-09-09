import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from scripts.init_db import seed_db
from tests.conftest import engine_test_async
from tests.factories.role import RoleFactory


@pytest.fixture
def urls(get_app):
    class URLs:
        def __init__(self, app):
            self.app = app

        def get_all_roles(self):
            return self.app.url_path_for("get_all_roles")

        def get_role(self, role_id: int):
            return self.app.url_path_for("get_role", role_id=role_id)

        def create_role(self):
            return self.app.url_path_for("create_role")

        def update_role(self, role_id: int):
            return self.app.url_path_for("update_role", role_id=role_id)

        def delete_role(self, role_id: int):
            return self.app.url_path_for("delete_role", role_id=role_id)  # Fixed this line

    return URLs(get_app)


@pytest.mark.asyncio
class TestRoleEndpoint:

    async def test_get_all_roles(self, client: AsyncClient, urls):
        response = await client.get(urls.get_all_roles())
        assert response.status_code == 200

    async def test_get_role(self, client: AsyncClient, urls, db: AsyncSession):  # Use 'db' fixture
        role = RoleFactory.build()
        db.add(role)
        await db.commit()
        await db.refresh(role)

        response = await client.get(urls.get_role(role.id))
        assert response.status_code == 200
        assert response.json()["name"] == role.name
        assert response.json()["description"] == role.description

    async def test_create_role(self, client: AsyncClient, urls, db: AsyncSession):  # Use 'db' fixture
        role = RoleFactory.build()
        payload = {
            "name": role.name,
            "description": role.description
        }
        response = await client.post(urls.create_role(), json=payload)
        assert response.status_code == 201

    async def test_create_two_same_roles(self, client: AsyncClient, urls, db: AsyncSession):  # Use 'db' fixture
        role = RoleFactory.build()
        db.add(role)
        await db.commit()
        await db.refresh(role)

        payload = {
            "name": role.name,
            "description": role.description
        }
        response = await client.post(urls.create_role(), json=payload)
        assert response.status_code == 409

    async def test_update_role(self, client: AsyncClient, urls, db: AsyncSession):  # Use 'db' fixture
        role = RoleFactory.build()
        db.add(role)
        await db.commit()
        await db.refresh(role)

        payload = {
            "name": 'updated name',
            "description": 'updated description'
        }
        response = await client.put(urls.update_role(role.id), json=payload)
        assert response.status_code == 200
        assert response.json()["name"] == payload["name"]
        assert response.json()["description"] == payload["description"]

    async def test_update_nonexistent_role(self, client: AsyncClient, urls, db: AsyncSession):  # Use 'db' fixture
        payload = {
            "name": 'updated name',
            "description": 'updated description'
        }
        response = await client.put(urls.update_role(5000), json=payload)
        assert response.status_code == 404

    async def test_delete_role(self, client: AsyncClient, urls, db: AsyncSession):  # Use 'db' fixture
        role = RoleFactory.build()
        db.add(role)
        await db.commit()
        await db.refresh(role)
        response = await client.delete(urls.delete_role(role.id))  # Fixed to use delete_role instead of update_role
        assert response.status_code == 204