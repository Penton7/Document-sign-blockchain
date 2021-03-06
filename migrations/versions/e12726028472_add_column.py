"""add column

Revision ID: e12726028472
Revises: 4b26a2018908
Create Date: 2020-02-25 12:16:57.229890

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e12726028472'
down_revision = '4b26a2018908'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('roles', sa.String(length=120), nullable=False, server_default=("user")))
    op.create_foreign_key(None, 'documents', 'users', ['author'], ['username'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('users', 'roles')
    # ### end Alembic commands ###
