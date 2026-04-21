"""rebuild schema clean

Revision ID: 90d054dce8e2
Revises: 
Create Date: 2026-04-20 16:31:41.147636

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '90d054dce8e2'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column('prediction', 'player_name')

    op.alter_column(
        'prediction',
        'player_id',
        existing_type=sa.INTEGER(),
        nullable=False
    )

    op.alter_column(
        'prediction',
        'draft_position_group',
        existing_type=sa.TEXT(),
        type_=sa.String(length=50),
        existing_nullable=True
    )

    op.create_foreign_key(
        "fk_prediction_player_id",
        "prediction",
        "player",
        ["player_id"],
        ["id"]
    )


def downgrade():
    op.add_column(
        'prediction',
        sa.Column('player_name', sa.VARCHAR(length=100), nullable=True)
    )

    op.drop_constraint(
        "fk_prediction_player_id",
        "prediction",
        type_="foreignkey"
    )

    op.alter_column(
        'prediction',
        'draft_position_group',
        existing_type=sa.String(length=50),
        type_=sa.TEXT(),
        existing_nullable=True
    )

    op.alter_column(
        'prediction',
        'player_id',
        existing_type=sa.INTEGER(),
        nullable=True
    )
