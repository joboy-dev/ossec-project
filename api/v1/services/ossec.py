import subprocess

from api.utils.loggers import create_logger
from api.utils.settings import BASE_DIR

logger = create_logger(__name__, "logs/ossec.log")

class OssecService:
    
    def __init__(self):
        self.services = [
            "ossec-monitord",
            "ossec-logcollector",
            "ossec-remoted",
            "ossec-syscheckd",
            "ossec-analysisd",
            "ossec-maild",
            "ossec-execd"
        ]
        
        self.ossec_processes = {
            "ossec-maild": "Mail Daemon",
            "ossec-execd": "Execution Daemon",
            "ossec-analysisd": "Analysis Daemon",
            "ossec-logcollector": "Log Collector",
            "ossec-remoted": "Remote Daemon",
            "ossec-syscheckd": "Syscheck Daemon",
            "ossec-monitord": "Monitor Daemon"
        }
        
    def format_ossec_process_name(self, service_name: str):
        """Get the name of the Ossec service"""
        
        return self.ossec_processes[service_name]
    
    def get_ossec_level_text(self, level: int) -> str:
        """
        Returns a string describing the severity of an OSSEC alert based on its level.
        - 0-3: info
        - 4-6: moderate
        - 7-9: high
        - 10+: critical
        """
        
        try:
            level = int(level)
        except Exception:
            return "unknown"

        if level <= 3:
            return "info"
        elif 4 <= level <= 6:
            return "moderate"
        elif 7 <= level <= 9:
            return "high"
        else:
            return "critical"
    
    def start_ossec(self):
        """Start the Ossec service"""
        try:
            subprocess.run(["sudo", "/var/ossec/bin/ossec-control", "start"], capture_output=True, text=True)
            logger.info("Ossec started successfully")
            return True
        except Exception as e:
            logger.error(f"Error starting Ossec: {e}")
            return False
    
    def stop_ossec(self):
        """Stop the Ossec service"""
        try:
            subprocess.run(["sudo", "/var/ossec/bin/ossec-control", "stop"], capture_output=True, text=True)
            logger.info("Ossec stopped successfully")
            return True
        except Exception as e:
            logger.error(f"Error stopping Ossec: {e}")
            return False
    
    def restart_ossec(self):
        """Restart the Ossec service"""
        try:
            subprocess.run(["sudo", "/var/ossec/bin/ossec-control", "restart"], capture_output=True, text=True)
            logger.info("Ossec restarted successfully")
            return True
        except Exception as e:
            logger.error(f"Error restarting Ossec: {e}")
            return False
    
    def get_ossec_status(self):
        """Get the status of the Ossec service"""
        try:
            result = subprocess.run(["sudo", "/var/ossec/bin/ossec-control", "status"], capture_output=True, text=True)
            print(result.stdout)
            
            status_dict = {}
            for service in self.services:
                if f"{service} not running" in result.stdout:
                    status_dict[service.replace("-", "_")] = False
                elif (
                    f"{service} is running" in result.stdout or 
                    f"{service} already running" in result.stdout or
                    f"Started {service}" in result.stdout
                ):
                    status_dict[service.replace("-", "_")] = True
                else:
                    status_dict[service.replace("-", "_")] = False  # Default to False if not found
                
            print(status_dict)
            return status_dict
        except Exception as e:
            logger.error(f"Error getting Ossec status: {e}")
            return None
        
    def sync_alerts(self):
        """Fetches alerts from osssec logs"""
        try:
            result = subprocess.run(["sudo", "bash", f"{BASE_DIR}/scripts/sync_ossec_alerts.sh"], capture_output=True, text=True)
            print(result.stdout)
            result2 = subprocess.run(["python3", f"{BASE_DIR}/scripts/load_alerts_into_db.py"], capture_output=True, text=True)
            print(result2.stdout)
            logger.info("Alerts synced successfully")
            return True
        except Exception as e:
            logger.error(f"Error syncing ossec alerts: {e}")
            return False

ossec_service = OssecService()
