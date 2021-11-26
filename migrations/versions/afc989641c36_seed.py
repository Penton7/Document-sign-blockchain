"""Events columns

Revision ID: afc989641c36
Revises: 4598f26e4707
Create Date: 2020-07-17 16:34:42.389130

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'afc989641c36'
down_revision = '4598f26e4707'
branch_labels = None
depends_on = None

def seed_data():

    role = sa.sql.table('role', sa.Column('id', sa.Integer(), nullable=False),
                        sa.Column('name', sa.String(length=120), nullable=True),
                        sa.Column('permissions', sa.JSON(), nullable=True),)
    op.bulk_insert(
        role,
        [
            {'id': 1, 'name': 'admin', 'permissions': [ "create_gmail", "change_gmail_password", "delete_gmail", "create_other_accounts", "block_other_accounts", "add_user_to_groups", "create_project", "logs", "admin_panel" ]},
        ]
    )
    user = sa.sql.table('users', sa.Column('id', sa.Integer(), nullable=False),
                        sa.Column('username', sa.String(length=120), nullable=False),
                        sa.Column('password', sa.String(length=120), nullable=False),
                        sa.Column('public_key', sa.String(length=120), nullable=False),
                        sa.Column('roles', sa.String(length=120), nullable=False))
    op.bulk_insert(
        user,
        [
            {'id': 1, 'username': 'admin', 'password': '827ccb0eea8a706c4c34a16891f84e7b', 'roles': 'admin', 'public_key':'GB5H5WZCEEIVF3Q7QQNARWHPGUKZFSYBI3DSZ3SBNBS3W6XFLPYM6II2'}
        ]
    )
    documents = sa.sql.table('documents', sa.Column('id', sa.Integer(), nullable=False),
                             sa.Column('document_name', sa.String(length=120), nullable=False),
                             sa.Column('author', sa.String(length=120), nullable=False),
                             sa.Column('doc_hash', sa.String(length=120), nullable=False),
                             sa.Column('sign', sa.Boolean(), nullable=False))

    op.bulk_insert(
        documents,
        [
            {'id': 2, 'document_name': 'test_1', 'author': 'admin', 'doc_hash': "3kjh123", "sign": True}
        ]
    )

def upgrade():
    seed_data()