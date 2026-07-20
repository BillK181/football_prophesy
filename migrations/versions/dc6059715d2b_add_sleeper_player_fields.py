"""Add Sleeper player fields

Revision ID: dc6059715d2b
Revises: 2524deb04fef
Create Date: 2026-07-13 15:46:36.981750

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "dc6059715d2b"
down_revision = "2524deb04fef"
branch_labels = None
depends_on = None


def upgrade():
    # Add Sleeper player fields
    with op.batch_alter_table("player", schema=None) as batch_op:

        batch_op.add_column(
            sa.Column("sleeper_id", sa.String(length=50), nullable=True)
        )

        batch_op.add_column(
            sa.Column("first_name", sa.String(length=50), nullable=True)
        )

        batch_op.add_column(
            sa.Column("last_name", sa.String(length=50), nullable=True)
        )

        batch_op.add_column(
            sa.Column("position", sa.String(length=10), nullable=True)
        )

        batch_op.add_column(
            sa.Column("fantasy_positions", sa.JSON(), nullable=True)
        )

        batch_op.add_column(
            sa.Column("team", sa.String(length=10), nullable=True)
        )

        batch_op.add_column(
            sa.Column("number", sa.Integer(), nullable=True)
        )

        batch_op.add_column(
            sa.Column("college", sa.String(length=100), nullable=True)
        )

        batch_op.add_column(
            sa.Column("birth_country", sa.String(length=100), nullable=True)
        )

        batch_op.add_column(
            sa.Column("age", sa.Integer(), nullable=True)
        )

        batch_op.add_column(
            sa.Column("years_exp", sa.Integer(), nullable=True)
        )

        batch_op.add_column(
            sa.Column("height", sa.String(length=20), nullable=True)
        )

        batch_op.add_column(
            sa.Column("weight", sa.String(length=20), nullable=True)
        )


        # Status / injury information
        batch_op.add_column(
            sa.Column("status", sa.String(length=50), nullable=True)
        )

        batch_op.add_column(
            sa.Column("injury_status", sa.String(length=50), nullable=True)
        )

        batch_op.add_column(
            sa.Column("injury_start_date", sa.String(length=50), nullable=True)
        )

        batch_op.add_column(
            sa.Column("practice_participation", sa.String(length=50), nullable=True)
        )


        # Depth chart
        batch_op.add_column(
            sa.Column("depth_chart_position", sa.Integer(), nullable=True)
        )

        batch_op.add_column(
            sa.Column("depth_chart_order", sa.Integer(), nullable=True)
        )


        # Search fields
        batch_op.add_column(
            sa.Column("hashtag", sa.String(length=200), nullable=True)
        )

        batch_op.add_column(
            sa.Column("search_first_name", sa.String(length=100), nullable=True)
        )

        batch_op.add_column(
            sa.Column("search_last_name", sa.String(length=100), nullable=True)
        )

        batch_op.add_column(
            sa.Column("search_full_name", sa.String(length=150), nullable=True)
        )

        batch_op.add_column(
            sa.Column("search_rank", sa.Integer(), nullable=True)
        )


        # External IDs
        batch_op.add_column(
            sa.Column("fantasy_data_id", sa.Integer(), nullable=True)
        )

        batch_op.add_column(
            sa.Column("sportradar_id", sa.String(length=100), nullable=True)
        )

        batch_op.add_column(
            sa.Column("stats_id", sa.String(length=100), nullable=True)
        )

        batch_op.add_column(
            sa.Column("espn_id", sa.String(length=100), nullable=True)
        )

        batch_op.add_column(
            sa.Column("rotowire_id", sa.String(length=100), nullable=True)
        )

        batch_op.add_column(
            sa.Column("rotoworld_id", sa.Integer(), nullable=True)
        )

        batch_op.add_column(
            sa.Column("yahoo_id", sa.String(length=100), nullable=True)
        )


        # Sync tracking
        batch_op.add_column(
            sa.Column("last_updated", sa.DateTime(), nullable=True)
        )


def downgrade():

    with op.batch_alter_table("player", schema=None) as batch_op:

        batch_op.drop_column("last_updated")

        batch_op.drop_column("yahoo_id")
        batch_op.drop_column("rotoworld_id")
        batch_op.drop_column("rotowire_id")
        batch_op.drop_column("espn_id")
        batch_op.drop_column("stats_id")
        batch_op.drop_column("sportradar_id")
        batch_op.drop_column("fantasy_data_id")

        batch_op.drop_column("search_rank")
        batch_op.drop_column("search_full_name")
        batch_op.drop_column("search_last_name")
        batch_op.drop_column("search_first_name")

        batch_op.drop_column("hashtag")

        batch_op.drop_column("depth_chart_order")
        batch_op.drop_column("depth_chart_position")

        batch_op.drop_column("practice_participation")
        batch_op.drop_column("injury_start_date")
        batch_op.drop_column("injury_status")
        batch_op.drop_column("status")

        batch_op.drop_column("weight")
        batch_op.drop_column("height")
        batch_op.drop_column("years_exp")
        batch_op.drop_column("age")

        batch_op.drop_column("birth_country")
        batch_op.drop_column("college")

        batch_op.drop_column("number")
        batch_op.drop_column("team")

        batch_op.drop_column("fantasy_positions")
        batch_op.drop_column("position")

        batch_op.drop_column("last_name")
        batch_op.drop_column("first_name")

        batch_op.drop_column("sleeper_id")