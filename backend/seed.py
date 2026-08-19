import asyncio
from app.persistence.database import async_session_factory
from app.persistence.models.identity_models import UserModel
from app.auth.passwords import get_password_hash
from sqlalchemy.future import select

async def seed_users():
    users_to_create = [
        {"username": "admin_user", "email": "admin@netsleuth.local", "password": "testpass", "role": "administrator", "full_name": "Admin User"},
        {"username": "inv1", "email": "inv1@netsleuth.local", "password": "testpass", "role": "investigator", "full_name": "Investigator 1"},
        {"username": "inv2", "email": "inv2@netsleuth.local", "password": "testpass", "role": "investigator", "full_name": "Investigator 2"},
        {"username": "analyst1", "email": "analyst1@netsleuth.local", "password": "testpass", "role": "analyst", "full_name": "Analyst 1"},
    ]
    
    async with async_session_factory() as session:
        for u in users_to_create:
            result = await session.execute(select(UserModel).where(UserModel.username == u["username"]))
            existing = result.scalars().first()
            if not existing:
                hashed = get_password_hash(u["password"])
                new_user = UserModel(
                    username=u["username"],
                    email=u["email"],
                    hashed_password=hashed,
                    full_name=u["full_name"],
                    role=u["role"],
                    is_active=True
                )
                session.add(new_user)
                print(f"Created user {u['username']}")
            else:
                print(f"User {u['username']} already exists")
        
        await session.commit()
        print("Database seeded.")

if __name__ == "__main__":
    asyncio.run(seed_users())