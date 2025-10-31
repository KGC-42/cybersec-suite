\# Multi-Organization System



Universal multi-tenant organization management for any SaaS application.



\## Features

\- Organization management (create, update, delete)

\- Team member invitations via email

\- Role-based access control (Owner, Admin, Member, Viewer)

\- Permission system with decorators

\- Organization switching in UI

\- Configurable per-app via org.config.json



\## Quick Setup



\### 1. Add to Your App

python setup.py --app <your-app-name>



\### 2. Run Migrations

cd apps/<your-app>/backend

alembic upgrade head



\### 3. Add Router to FastAPI

from packages.multi\_org.backend.router import router as org\_router

app.include\_router(org\_router)



\## Database Schema

\- organizations - Org details

\- organization\_members - User-org relationships

\- organization\_invitations - Pending invites



\## API Endpoints

\- POST /api/v1/orgs - Create organization

\- GET /api/v1/orgs - List user's organizations

\- GET /api/v1/orgs/{org\_id} - Get organization details

\- POST /api/v1/orgs/{org\_id}/invitations - Invite member

\- GET /api/v1/orgs/{org\_id}/members - List members

