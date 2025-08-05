from sqlalchemy import Column, String, Integer, DateTime, Text
from api.core.base.base_model import BaseTableModel
from sqlalchemy.sql import func

class Alert(BaseTableModel):
    __tablename__ = "alerts"

    rule_id = Column(String(16), nullable=False)
    level = Column(Integer, nullable=False)
    level_meaning = Column(String(512), nullable=True)
    level_text = Column(String(16), nullable=True)
    description = Column(String(256), nullable=True)
    user = Column(String(64), nullable=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)  # ISO format string
    hostname = Column(String(128), nullable=True)
    device_ip = Column(String(64), nullable=True)
    log_file_path = Column(String(256), nullable=True)
    log = Column(Text, nullable=True)
