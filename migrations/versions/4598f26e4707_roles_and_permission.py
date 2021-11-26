"""Roles and Permission

Revision ID: 4598f26e4707
Revises: e12726028472
Create Date: 2020-02-26 15:51:32.301028

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4598f26e4707'
down_revision = 'e12726028472'
branch_labels = None
depends_on = None



def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('role',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=True),
    sa.Column('permissions', sa.JSON(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_foreign_key(None, 'users', 'role', ['roles'], ['name'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='foreignkey')
    op.drop_table('role')
    # ### end Alembic commands ###
