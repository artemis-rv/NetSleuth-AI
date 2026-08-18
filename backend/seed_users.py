import asyncio
import os
import sys

# Ensure backend root is on python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app.persistence.database import async_session_factory
from app.persistence.models.identity_models import UserModel
from app.persistence.repositories.identity_repository import UserRepository
from app.auth.passwords import get_password_hash

async def seed_users():
    print("Seeding database users...")
    users_to_create = [
        {
            "username": "admin_user",
            "email": "admin@netsleuth.ai",
            "full_name": "Administrator",
            "password": "testpass",
            "role": "administrator",
        },
        {
            "username": "inv1",
            "email": "inv1@netsleuth.ai",
            "full_name": "Investigator 1",
            "password": "testpass",
            "role": "investigator",
        },
        {
            "username": "inv2",
            "email": "inv2@netsleuth.ai",
            "full_name": "Investigator 2",
            "password": "testpass",
            "role": "investigator",
        },
    ]

    async with async_session_factory() as session:
        repo = UserRepository(session)
        for udata in users_to_create:
            existing = await repo.get_by_username(udata["username"])
            if existing:
                print(f"User '{udata['username']}' already exists.")
            else:
                hashed = get_password_hash(udata["password"])
                new_user = UserModel(
                    username=udata["username"],
                    email=udata["email"],
                    full_name=udata["full_name"],
                    hashed_password=hashed,
                    role=udata["role"],
                    is_active=True,
                )
                session.add(new_user)
                await session.commit()
                print(f"Created user '{udata['username']}' with role '{udata['role']}'.")

if __name__ == "__main__":
    asyncio.run(seed_users())
