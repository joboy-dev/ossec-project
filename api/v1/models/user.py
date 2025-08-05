import sqlalchemy as sa
from sqlalchemy import event
from sqlalchemy.orm import relationship, Session
from datetime import datetime, timezone

from api.core.base.base_model import BaseTableModel


class User(BaseTableModel):
    __tablename__ = 'users'
    
    email = sa.Column(sa.String, nullable=True, unique=True, index=True)
    username = sa.Column(sa.String, nullable=True, unique=True, index=True)
    password = sa.Column(sa.String, nullable=True)
    is_active = sa.Column(sa.Boolean, default=False)
    is_admin = sa.Column(sa.Boolean, default=False)
    last_login = sa.Column(sa.DateTime(timezone=True), default=datetime.now(timezone.utc))
    
    def to_dict(self, excludes=[]):
        return super().to_dict(excludes=excludes+['password'])
