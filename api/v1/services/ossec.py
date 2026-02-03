import time
# from datetime import time
import os
import subprocess
import xml.etree.ElementTree as ET

from api.utils.files import count_lines_in_file
from api.utils.loggers import create_logger
from api.utils.paginator import read_file_paginated
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
        
    def backup_ossec_config(self, config_path: str = "/var/ossec/etc/ossec.conf", backup_path: str = None):
        """
        Create a backup copy of the ossec.conf file.
        If backup_path is not provided, appends '.bak' to config_path.
        """
        import shutil
        if backup_path is None:
            backup_path = config_path + ".bak"
        shutil.copy2(config_path, backup_path)
        logger.info(f"Backup of ossec.conf created at {backup_path}")
        return backup_path
    
    def sync_monitored_files(self):
        """Gets monitored file and copies them into a new file accessible by the application."""
        try:
            result = subprocess.run(["sudo", "bash", f"{BASE_DIR}/scripts/sync_monitored_files.sh"], capture_output=True, text=True)
            print(result.stdout)
            logger.info("Monitored files synced successfully")
            return True
        except Exception as e:
            logger.error(f"Error syncing monitored files: {e}")
            return False
        
    def get_all_monitored_files(self, offset: int = 0, limit: int = 20):
        def parse_syscheck_line(line: str):
            # Example: +++34:33188:0:0:4317c6de8564b68d628c21efa96b37e4:addee0472ac552e7c43db27234ee260282b9b988 !1753951311 /etc/ld.so.conf
            try:
                # Split status and the rest
                status = line[:3]
                rest = line[3:].strip()
                # Find the " !" separator for meta and file path
                meta_split = rest.split(" !", 1)
                if len(meta_split) != 2:
                    return None
                meta_fields = meta_split[0]
                last_check_and_path = meta_split[1].strip()
                # last_check is the first word, path is the rest
                last_check, *file_path_parts = last_check_and_path.split()
                file_path = " ".join(file_path_parts)
                # meta_fields: version:inode:dev_major:dev_minor:md5:sha1
                meta_parts = meta_fields.split(":")
                if len(meta_parts) != 6:
                    return None
                version, inode, dev_major, dev_minor, md5, sha1 = meta_parts
                # File info
                if os.path.exists(file_path):
                    st = os.stat(file_path)
                    size = f"{st.st_size / 1024:.1f} KB"
                    permissions = oct(st.st_mode & 0o777)[2:]
                    last_modified = time.strftime("%m/%d/%Y, %I:%M:%S %p", time.localtime(st.st_mtime))
                else:
                    size = "0 B"
                    permissions = "N/A"
                    last_modified = "N/A"
                status_map = {
                    "+++": "New File",
                    "---": "Deleted",
                    "...": "Modified",
                    "!!!": "Integrity Error"
                }
                try:
                    last_checked = time.strftime("%m/%d/%Y, %I:%M:%S %p", time.localtime(int(last_check)))
                except Exception:
                    last_checked = "N/A"
                return {
                    "path": file_path,
                    "status": status_map.get(status, "Verified"),
                    "size": size,
                    "permissions": permissions,
                    "last_modified": last_modified,
                    "current": sha1,
                    "baseline": md5,
                    "last_checked": last_checked
                }
            except Exception as e:
                logger.error(f"Failed to parse syscheck line: {e}")
                return None

        files = []
        file_path = f"{BASE_DIR}/logs/syscheck"
        # file_path = f"/var/ossec/queue/syscheck/syscheck"
        
        if not os.path.exists(file_path):
            # Create an empty file if it does not exist
            with open(file_path, "w"):
                pass

        total = count_lines_in_file(file_path)
        lines = read_file_paginated(file_path, offset=offset, limit=limit)
        for line in lines:
            data = parse_syscheck_line(line)
            if data:
                files.append(data)

        return files, total
        
    def get_monitored_paths(self, config_path: str="/var/ossec/etc/ossec.conf"):
        tree = ET.parse(config_path)
        root = tree.getroot()

        namespaces = {"ossec": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        
        monitored = []
        for syscheck in root.findall(".//syscheck", namespaces):
            for dirs in syscheck.findall("directories", namespaces):
                text = (dirs.text or "").strip()
                if text:
                    monitored.extend(p.strip() for p in text.split(",") if p.strip())
        return monitored
    
    def add_monitored_path(self, new_path: str, config_path: str="/var/ossec/etc/ossec.conf"):
        self.backup_ossec_config()
        
        tree = ET.parse(config_path)
        root = tree.getroot()
        
        syscheck = root.find(".//syscheck")
        if syscheck is None:
            syscheck = ET.SubElement(root, "syscheck")
        
        directories = syscheck.find("directories")
        if directories is None:
            directories = ET.SubElement(syscheck, "directories")
            directories.text = new_path
        else:
            dirs = set(directories.text.split(","))
            dirs.add(new_path)
            directories.text = ",".join(sorted(dirs))
        
        tree.write(config_path)
        
        # Restart OSSEC
        self.restart_ossec()

    def remove_monitored_path(self, path: str, config_path: str = "/var/ossec/etc/ossec.conf"):
        """Remove a path from monitored directories."""
        self.backup_ossec_config()
        tree = ET.parse(config_path)
        root = tree.getroot()
        syscheck = root.find(".//syscheck")
        if syscheck is None:
            return
        for directories in syscheck.findall("directories"):
            dirs = [d.strip() for d in (directories.text or "").split(",") if d.strip()]
            if path in dirs:
                dirs = [d for d in dirs if d != path]
                directories.text = ",".join(dirs) if dirs else ""
                if not dirs:
                    syscheck.remove(directories)
                break
        tree.write(config_path)
        self.restart_ossec()
        
    def update_monitored_path_attribute(
        self, 
        path: str, 
        attr: str, 
        value: str, 
        config_path: str="/var/ossec/etc/ossec.conf"
    ):
        """
        Update or add an attribute for a monitored directory in <directories> under <syscheck>.
        If the attribute does not exist, it will be created.
        """
        self.backup_ossec_config()
        tree = ET.parse(config_path)
        root = tree.getroot()
        syscheck = root.find(".//syscheck")
        if syscheck is None:
            raise ValueError("No <syscheck> section found in config.")

        updated = False
        for directories in syscheck.findall("directories"):
            dirs = [d.strip() for d in (directories.text or "").split(",")]
            if path in dirs:
                if directories.get(attr) != value:
                    directories.set(attr, value)
                updated = True
                
        if not updated:
            # Add a new <directories> element for this path with the attribute
            new_elem = ET.SubElement(syscheck, "directories")
            new_elem.text = path
            new_elem.set(attr, value)
        tree.write(config_path)
        self.restart_ossec()
        
    def get_ignored_paths(self, config_path: str="/var/ossec/etc/ossec.conf"):
        
        tree = ET.parse(config_path)
        root = tree.getroot()

        namespaces = {"ossec": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
        
        ignored = []
        for syscheck in root.findall(".//syscheck", namespaces):
            for ignore_elem in syscheck.findall("ignore", namespaces):
                text = (ignore_elem.text or "").strip()
                if text:
                    ignored.extend(p.strip() for p in text.split(",") if p.strip())
        return ignored
    
    def add_ignored_path(self, new_path: str, config_path: str="/var/ossec/etc/ossec.conf"):
        self.backup_ossec_config()
        
        tree = ET.parse(config_path)
        root = tree.getroot()
        
        syscheck = root.find(".//syscheck")
        if syscheck is None:
            syscheck = ET.SubElement(root, "syscheck")
        
        ignore = syscheck.find("ignore")
        if ignore is None:
            ignore = ET.SubElement(syscheck, "ignore")
            ignore.text = new_path
        else:
            dirs = set(ignore.text.split(","))
            dirs.add(new_path)
            ignore.text = ",".join(sorted(dirs))
        
        tree.write(config_path)
        
        # Restart OSSEC
        self.restart_ossec()

    def remove_ignored_path(self, path: str, config_path: str = "/var/ossec/etc/ossec.conf"):
        """Remove a path from ignored directories."""
        self.backup_ossec_config()
        tree = ET.parse(config_path)
        root = tree.getroot()
        syscheck = root.find(".//syscheck")
        if syscheck is None:
            return
        for ignore in syscheck.findall("ignore"):
            dirs = [d.strip() for d in (ignore.text or "").split(",") if d.strip()]
            if path in dirs:
                dirs = [d for d in dirs if d != path]
                ignore.text = ",".join(dirs) if dirs else ""
                if not dirs:
                    syscheck.remove(ignore)
                break
        tree.write(config_path)
        self.restart_ossec()
    
    def set_syscheck_tag(self, tag: str, value: str, config_path: str = "/var/ossec/etc/ossec.conf"):
        """
        Add or update a syscheck child tag (frequency, scan_time, scan_day, auto_ignore, alert_new_files, scan_on_start, skip_nfs).
        """
        self.backup_ossec_config(config_path)
        tree = ET.parse(config_path)
        root = tree.getroot()
        syscheck = root.find(".//syscheck")
        if syscheck is None:
            syscheck = ET.SubElement(root, "syscheck")
        tag_elem = syscheck.find(tag)
        if tag_elem is None:
            tag_elem = ET.SubElement(syscheck, tag)
        tag_elem.text = str(value)
        tree.write(config_path)
        self.restart_ossec()

    def get_syscheck_tag(self, tag: str, config_path: str = "/var/ossec/etc/ossec.conf"):
        """
        Get the value of a syscheck child tag.
        """
        tree = ET.parse(config_path)
        root = tree.getroot()
        syscheck = root.find(".//syscheck")
        if syscheck is not None:
            tag_elem = syscheck.find(tag)
            if tag_elem is not None and tag_elem.text is not None:
                return tag_elem.text.strip()
        return None
    
    def set_global_tag(self, tag: str, value: str, config_path: str = "/var/ossec/etc/ossec.conf"):
        """
        Add or update a tag in the <global> section of ossec.conf.
        """
        self.backup_ossec_config(config_path)
        tree = ET.parse(config_path)
        root = tree.getroot()
        global_elem = root.find(".//global")
        if global_elem is None:
            global_elem = ET.SubElement(root, "global")
        tag_elem = global_elem.find(tag)
        if tag_elem is None:
            tag_elem = ET.SubElement(global_elem, tag)
        tag_elem.text = str(value)
        tree.write(config_path)
        self.restart_ossec()

    def get_global_tag(self, tag: str, config_path: str = "/var/ossec/etc/ossec.conf"):
        """Get the value of a tag in the <global> section."""
        tree = ET.parse(config_path)
        root = tree.getroot()
        global_elem = root.find(".//global")
        if global_elem is not None:
            tag_elem = global_elem.find(tag)
            if tag_elem is not None and tag_elem.text is not None:
                return tag_elem.text.strip()
        return None

ossec_service = OssecService()
