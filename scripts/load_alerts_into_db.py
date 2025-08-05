from datetime import datetime
import sys
import pathlib
import os
import json

ROOT_DIR = pathlib.Path(__file__).parent.parent

# ADD PROJECT ROOT TO IMPORT SEARCH SCOPE
sys.path.append(str(ROOT_DIR))

from api.v1.services.ossec import ossec_service
from api.db.database import get_db_with_ctx_manager
from api.v1.models.alert import Alert


def load_alerts_from_file(file_path: str):
    with open(file_path, "r") as f:
        alerts_data = json.load(f)
        
        with get_db_with_ctx_manager() as db:
            existing_ids = set(
                row[0] for row in db.query(Alert.unique_id).filter(
                    Alert.unique_id.in_([a.get("alert_id") for a in alerts_data if a.get("alert_id")])
                ).all()
            )
            
            alerts_data = [a for a in alerts_data if a.get("alert_id") not in existing_ids]
            for alert in alerts_data:
                Alert.create(
                    db=db,
                    unique_id=alert.get("alert_id"),
                    rule_id=alert.get("rule_id"),
                    level=alert.get("level"),
                    level_meaning=alert.get("level_meaning"),
                    level_text=ossec_service.get_ossec_level_text(alert.get("level")),
                    description=alert.get("description"),
                    user=alert.get("user"),
                    timestamp=datetime.fromisoformat(alert.get("timestamp")) if alert.get("timestamp") else None,
                    hostname=alert.get("hostname"),
                    device_ip=alert.get("device_ip"),
                    log_file_path=alert.get("log_file_path"),
                    log=alert.get("log"),
                )
                print(f"Inserted alert {alert.get('alert_id')}")
            
if __name__ == "__main__":
    for directory in os.listdir("logs/ossec-alerts"):
        dir_path = os.path.join("logs/ossec-alerts", directory)
        alerts_file = os.path.join(dir_path, "alerts.json")
        if os.path.isdir(dir_path) and os.path.isfile(alerts_file):
            print(f"Loading alerts from {alerts_file}")
            load_alerts_from_file(alerts_file)
        else:
            print(f"Skipping {dir_path} because it is not a directory or does not contain alerts.json")