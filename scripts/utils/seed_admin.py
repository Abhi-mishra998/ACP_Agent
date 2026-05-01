#!/usr/bin/env python3
"""
Seed database with initial admin user for ACP system.
Uses raw SQL to avoid ORM/enum version mismatches across container rebuilds.
Safe to re-run: skips if admin already exists.
"""

import asyncio
import sys
import uuid
from pathlib import Path

import bcrypt

sys.path.insert(0, str(Path(__file__).parent))

ADMIN_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def resolve_database_url(original_url: str) -> str:
    if "acp_postgres" in original_url:
        original_url = original_url.replace("acp_postgres:5432", "localhost:5433")
    if original_url.endswith("/acp"):
        original_url = original_url.replace("/acp", "/acp_identity")
    return original_url


async def seed_admin_user() -> bool:
    try:
        from sqlalchemy import text
        from sqlalchemy.ext.asyncio import create_async_engine

        from services.identity.database import settings

        db_url = resolve_database_url(settings.DATABASE_URL)
        print(f"🔗 Using DB: {db_url}")

        engine = create_async_engine(db_url, echo=False)
        hashed_password = bcrypt.hashpw(b"password", bcrypt.gensalt()).decode("utf-8")
        admin_id = str(uuid.uuid4())

        async with engine.connect() as conn:
            # 1. Check if users table exists
            res = await conn.execute(text(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'users')"
            ))
            if not res.scalar():
                print("❌ 'users' table does not exist. Did you run migrations?")
                return False

            # 2. Check if admin already exists
            row = await conn.execute(
                text("SELECT id FROM users WHERE email = 'admin@acp.local' LIMIT 1")
            )
            if row.fetchone():
                print("✅ Admin user already exists (identity DB)")
                return True

            # 3. Check schema features
            has_org_id_res = await conn.execute(text(
                "SELECT EXISTS (SELECT FROM information_schema.columns WHERE table_name='users' AND column_name='org_id')"
            ))
            org_id_exists = has_org_id_res.scalar()

            has_tenants_res = await conn.execute(text(
                "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name='tenants')"
            ))
            tenants_exists = has_tenants_res.scalar()

            # 4. Perform Seed queries
            
            if tenants_exists:
                # Check if default admin tenant already exists
                t_res = await conn.execute(text(
                    f"SELECT id FROM tenants WHERE tenant_id = '{ADMIN_TENANT_ID}' LIMIT 1"
                ))
                if not t_res.fetchone():
                    print("🌱 Seeding default tenant...")
                    await conn.execute(text(
                        f"INSERT INTO tenants (id, org_id, tenant_id, name, tier, rpm_limit, is_active) "
                        f"VALUES ('{ADMIN_TENANT_ID}', '{ADMIN_TENANT_ID}', '{ADMIN_TENANT_ID}', "
                        f"'Default Admin Org', 'enterprise', 0, true)"
                    ))
                else:
                    print("✅ Default tenant already exists")
            
            print("🌱 Seeding admin user...")
            if org_id_exists:
                await conn.execute(text(
                    f"INSERT INTO users (id, email, hashed_password, role, is_active, "
                    f"tenant_id, org_id) VALUES "
                    f"('{admin_id}', 'admin@acp.local', '{hashed_password}', "
                    f"'ADMIN', true, '{ADMIN_TENANT_ID}', '{ADMIN_TENANT_ID}')"
                ))
            else:
                await conn.execute(text(
                    f"INSERT INTO users (id, email, hashed_password, role, is_active, "
                    f"tenant_id) VALUES "
                    f"('{admin_id}', 'admin@acp.local', '{hashed_password}', "
                    f"'ADMIN', true, '{ADMIN_TENANT_ID}')"
                ))
            
            await conn.commit()

        await engine.dispose()
        print("\n✅ Admin user created successfully")
        print("   Credentials: admin@acp.local / password")
        return True

    except Exception as e:
        print(f"\n❌ Seed failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = asyncio.run(seed_admin_user())
    sys.exit(0 if success else 1)
