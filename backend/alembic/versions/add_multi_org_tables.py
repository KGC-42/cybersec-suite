"""
Alembic Migration Template for Multi-Organization System
Copy this to your app's alembic/versions/ folder and run:
    alembic upgrade head
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'add_multi_org_tables'
down_revision = 'fd3e293696d0'
branch_labels = None
depends_on = None


def upgrade():
    # Create organizations table
    op.create_table(
        'organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('slug', sa.String(100), unique=True, nullable=False, index=True),
        sa.Column('owner_id', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('plan', sa.Enum('free', 'pro', 'enterprise', name='organizationplan'), nullable=False, server_default='free'),
        sa.Column('billing_email', sa.String(255)),
        sa.Column('max_members', sa.Integer, server_default='5'),
        sa.Column('max_resources', sa.Integer, server_default='10'),
        sa.Column('settings', sa.Text),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.text('now()')),
        sa.Column('updated_at', sa.DateTime, nullable=False, server_default=sa.text('now()'))
    )
    
    # Create organization_members table
    op.create_table(
        'organization_members',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.Integer, sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('role', sa.Enum('owner', 'admin', 'member', 'viewer', name='memberrole'), nullable=False, server_default='member'),
        sa.Column('invited_by', sa.Integer, sa.ForeignKey('users.id')),
        sa.Column('joined_at', sa.DateTime, nullable=False, server_default=sa.text('now()')),
        sa.UniqueConstraint('org_id', 'user_id', name='uq_org_user')
    )
    
    # Create organization_invitations table
    op.create_table(
        'organization_invitations',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('email', sa.String(255), nullable=False, index=True),
        sa.Column('role', sa.Enum('owner', 'admin', 'member', 'viewer', name='memberrole'), nullable=False, server_default='member'),
        sa.Column('token', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('status', sa.Enum('pending', 'accepted', 'expired', 'revoked', name='invitationstatus'), nullable=False, server_default='pending'),
        sa.Column('invited_by', sa.Integer, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False, server_default=sa.text('now()')),
        sa.Column('expires_at', sa.DateTime, nullable=False),
        sa.Column('accepted_at', sa.DateTime)
    )
    
    # Add org_id to existing tables
    op.add_column('agents', sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id')))
    op.add_column('security_events', sa.Column('org_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('organizations.id')))


def downgrade():
    # Remove org_id from existing tables
    op.drop_column('security_events', 'org_id')
    op.drop_column('agents', 'org_id')
    
    # Drop tables in reverse order
    op.drop_table('organization_invitations')
    op.drop_table('organization_members')
    op.drop_table('organizations')
    
    # Drop enums
    op.execute('DROP TYPE IF EXISTS invitationstatus')
    op.execute('DROP TYPE IF EXISTS memberrole')
    op.execute('DROP TYPE IF EXISTS organizationplan')