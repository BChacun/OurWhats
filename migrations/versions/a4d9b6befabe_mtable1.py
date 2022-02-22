"""mtable1

Revision ID: a4d9b6befabe
Revises: 9e41976c97f4
Create Date: 2022-02-22 11:47:31.889940

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4d9b6befabe'
down_revision = '9e41976c97f4'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('groupMembers')
    op.drop_table('groups')
    op.add_column('messages', sa.Column('recipient_username', sa.String(), nullable=True))
    op.drop_column('messages', 'timestamp')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('messages', sa.Column('timestamp', sa.DATETIME(), nullable=True))
    op.drop_column('messages', 'recipient_username')
    op.create_table('groups',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('creator', sa.VARCHAR(), nullable=True),
    sa.Column('body', sa.VARCHAR(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('groupMembers',
    sa.Column('group_id', sa.INTEGER(), nullable=True),
    sa.Column('user_id', sa.INTEGER(), nullable=True),
    sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], )
    )
    # ### end Alembic commands ###