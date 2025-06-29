"""Add is_admin and Course

Revision ID: fca4a3693b83
Revises: b46b9ccafd5d
Create Date: 2025-06-28 21:17:28.576283

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'fca4a3693b83'
down_revision = 'b46b9ccafd5d'
branch_labels = None
depends_on = None


def upgrade():
    # Only add the is_admin column, do NOT create the course table if it already exists
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_admin', sa.Boolean(), nullable=True, server_default='0'))


def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('is_admin')
    # Do NOT drop the course table if it was not created by this migration
