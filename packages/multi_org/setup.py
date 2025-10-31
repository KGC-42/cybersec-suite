"""
Setup script to add multi-org to any app
Usage: python setup.py --app <app-name>
"""
import json
import shutil
import argparse
from pathlib import Path


def setup_multi_org(app_name: str):
    """Add multi-org system to an app"""
    
    # Paths
    root = Path(__file__).parent.parent.parent
    app_path = root / "apps" / app_name
    
    if not app_path.exists():
        print(f"❌ App not found: {app_path}")
        return
    
    print(f"🚀 Setting up multi-org for {app_name}...")
    
    # 1. Create config file
    config_path = app_path / "org.config.json"
    if not config_path.exists():
        config = {
            "app_id": app_name.replace("_", "-"),
            "app_name": app_name.replace("_", " ").title(),
            "features": {
                "multi_org": True,
                "invitations": True,
                "role_based_access": True
            },
            "roles": ["owner", "admin", "member", "viewer"],
            "default_role": "member",
            "plans": {
                "free": {
                    "max_members": 3,
                    "max_resources": 5
                },
                "pro": {
                    "max_members": 10,
                    "max_resources": 25
                },
                "enterprise": {
                    "max_members": -1,
                    "max_resources": -1
                }
            }
        }
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"✅ Created org.config.json")
    else:
        print(f"⚠️  org.config.json already exists, skipping")
    
    # 2. Copy migration template
    backend_path = app_path / "backend"
    if backend_path.exists():
        alembic_path = backend_path / "alembic" / "versions"
        if alembic_path.exists():
            migration_template = Path(__file__).parent / "backend" / "migrations" / "template.py"
            target = alembic_path / "add_multi_org_tables.py"
            
            if not target.exists():
                shutil.copy(migration_template, target)
                print(f"✅ Copied migration template to {target}")
            else:
                print(f"⚠️  Migration already exists, skipping")
        else:
            print(f"⚠️  Alembic not found, skipping migration")
    
    # 3. Instructions
    print("\n" + "="*60)
    print("✅ Multi-org setup complete!")
    print("="*60)
    print("\nNext steps:")
    print(f"1. Review and edit: {config_path}")
    print(f"2. Run migrations: cd {backend_path} && alembic upgrade head")
    print("3. Add router to main.py:")
    print("   from packages.multi_org.backend.router import router as org_router")
    print("   app.include_router(org_router)")
    print("\n4. Add org_id to your existing tables:")
    print("   - Uncomment lines in migration template")
    print("   - Update all queries to filter by org_id")
    print("\n5. Add OrgSwitcher to your frontend navbar")
    print("="*60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Setup multi-org for an app")
    parser.add_argument("--app", required=True, help="App name (e.g., cybersec-suite)")
    args = parser.parse_args()
    
    setup_multi_org(args.app)