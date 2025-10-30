"""Add users table and email notifications

Revision ID: fd3e293696d0
Revises: 708db532bdd6
Create Date: 2025-10-30 02:02:42.500029

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'fd3e293696d0'
down_revision: Union[str, None] = '708db532bdd6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255), nullable=True),
        sa.Column('notification_email', sa.String(255), nullable=True),
        sa.Column('email_notifications_enabled', sa.Boolean(), nullable=True, server_default='true'),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)
    
    # Add user_id to agents table
    op.add_column('agents', sa.Column('user_id', sa.Integer(), nullable=True))
    op.create_foreign_key('fk_agents_user_id', 'agents', 'users', ['user_id'], ['id'])

def downgrade() -> None:
    # Remove user_id from agents
    op.drop_constraint('fk_agents_user_id', 'agents', type_='foreignkey')
    op.drop_column('agents', 'user_id')
    
    # Drop users table
    op.drop_index('ix_users_email', 'users')
    op.drop_table('users')