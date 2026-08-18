"""season prediction scoring

Revision ID: 3dd3da66b3f2
Revises: c571a434e733
Create Date: 2026-08-12 16:56:42.998078

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3dd3da66b3f2'
down_revision = 'c571a434e733'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'player',
        sa.Column('season_prediction', sa.JSON(), nullable=True)
    )


def downgrade():
    op.drop_column('player', 'season_prediction')
