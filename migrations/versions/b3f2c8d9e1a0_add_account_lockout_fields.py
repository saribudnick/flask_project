"""Add account lockout fields

Revision ID: b3f2c8d9e1a0
Revises: a8f50ea9e8f1
Create Date: 2025-12-31 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b3f2c8d9e1a0'
down_revision = '8ae6011e3efa'
branch_labels = None
depends_on = None


def upgrade():
    # Add account lockout columns
    op.add_column('user', sa.Column('failed_login_attempts', sa.Integer(), nullable=True))
    op.add_column('user', sa.Column('locked_until', sa.DateTime(), nullable=True))
    
    # Set default value for existing rows
    op.execute("UPDATE user SET failed_login_attempts = 0 WHERE failed_login_attempts IS NULL")
    
    # Make failed_login_attempts non-nullable after setting defaults
    with op.batch_alter_table('user') as batch_op:
        batch_op.alter_column('failed_login_attempts',
                              existing_type=sa.Integer(),
                              nullable=False,
                              server_default='0')


def downgrade():
    with op.batch_alter_table('user') as batch_op:
        batch_op.drop_column('locked_until')
        batch_op.drop_column('failed_login_attempts')

