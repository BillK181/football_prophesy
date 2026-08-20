"""add game to predictions

Revision ID: acfd1049d70b
Revises: 48cff0484edd
Create Date: 2026-08-19 13:47:42.791353

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'acfd1049d70b'
down_revision = '48cff0484edd'
branch_labels = None
depends_on = None


def upgrade():

    with op.batch_alter_table('prediction', schema=None) as batch_op:

        batch_op.add_column(
            sa.Column(
                'game_id',
                sa.Integer(),
                nullable=True
            )
        )

        batch_op.create_foreign_key(
            'fk_prediction_game',
            'game',
            ['game_id'],
            ['id']
        )


def downgrade():

    with op.batch_alter_table('prediction', schema=None) as batch_op:

        batch_op.drop_constraint(
            'fk_prediction_game',
            type_='foreignkey'
        )

        batch_op.drop_column('game_id')