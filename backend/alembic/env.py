# backend/alembic/env.py

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import sys
from pathlib import Path

# --- FIX PATHS ---
# Start from this file → backend/alembic/env.py
# Go up to SAAS Scaffolding root (where 'packages' lives)
current_file = Path(__file__).resolve()
backend_dir = current_file.parent.parent         # backend/
cybersec_dir = backend_dir.parent                # cybersec-suite/
apps_dir = cybersec_dir.parent                   # apps/
root_dir = apps_dir.parent                       # SAAS Scaffolding/
sys.path.insert(0, str(root_dir))                # ✅ This is where 'packages' lives
sys.path.insert(0, str(backend_dir))

print("\n[DEBUG] sys.path entries (first 3):")
print(sys.path[:3])
print("[DEBUG] Root directory added:", root_dir)

# --- IMPORT YOUR MODELS ---
try:
    from app.models.security import Base
    from app.models.security import Agent, SecurityEvent
    print("✅ Successfully imported models from packages.db.models and app.models.security")
except ModuleNotFoundError as e:
    print("❌ Import error:", e)
    print("Check that you have 'packages/db/models.py' and 'backend/app/models/security.py'")
    raise

# --- ALEMBIC CONFIG ---
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
