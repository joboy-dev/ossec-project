from datetime import datetime
import psutil, os, time

from api.utils.loggers import create_logger


logger = create_logger(__name__)

class SystemResourceService:
    
    def format_bytes(cls, bytes):
        """Convert bytes to MB"""
        return round(bytes / (1024 * 1024), 2)
    
    @classmethod
    def get_system_resource_usage(cls):
        # Disk Usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent

        # Memory Usage
        mem = psutil.virtual_memory()
        mem_percent = mem.percent

        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=1)

        # Network IO
        net_io = psutil.net_io_counters()
        network = {
            "bytes_sent": net_io.bytes_sent,
            "bytes_recv": net_io.bytes_recv
        }

        # System Uptime
        uptime_seconds = int(time.time() - psutil.boot_time())
        uptime_hours = uptime_seconds // 3600
        uptime_minutes = (uptime_seconds % 3600) // 60
        uptime_secs = uptime_seconds % 60

        # Get CPU Count
        cpu_count = psutil.cpu_count()

        return {
            "disk_usage_percent": disk_percent,
            "memory_usage_percent": mem_percent,
            "cpu_usage_percent": cpu_percent,
            "network_io": network,
            "uptime": f'{uptime_hours}h {uptime_minutes}m {uptime_secs}s',
            "cpu_count": cpu_count
        }
    
    
    @classmethod
    def get_processes_info(cls, limit=20, skip=0):
        """
        Get info for system processes, with optional skip and limit for speed.
        Args:
            limit (int): Max number of processes to return.
            skip (int): Number of processes to skip from the start.
        """
        
        processes = []
        all_procs = list(psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info', 'create_time']))[::-1]
        
        count = 0
        for i, proc in enumerate(all_procs):
            if i < skip:
                continue
            if count >= limit:
                break
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                user = proc.info['username']
                cpu = proc.info.get('cpu_percent', 0.0)
                # Avoid calling cpu_percent() if already prefetched
                if cpu is None or cpu == 0.0:
                    cpu = proc.cpu_percent(interval=0.0)
                memory = round(proc.info['memory_info'].rss / (1024 * 1024), 2)  # MB
                start = datetime.fromtimestamp(proc.info['create_time'])
                start_time = start.strftime("%Y-%m-%d %H:%M:%S")
                
                uptime_seconds = (datetime.now() - start).seconds
                uptime_days = uptime_seconds // 86400
                uptime_hours = (uptime_seconds % 86400) // 3600
                uptime_str = f'{uptime_days}d {uptime_hours}h'
                ppid = proc.ppid()
                path = proc.exe()
                
                status = "Normal"
                
                try:
                    cmdline = proc.cmdline()
                except Exception:
                    cmdline = []
                if '/tmp' in path or '--hidden' in cmdline or cpu > 10:
                    status = "Suspicious"
                
                processes.append({
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "user": user,
                    "cpu": cpu,
                    "memory": memory,
                    "path": path,
                    "start_time": start_time,
                    "uptime": uptime_str,
                    "status": status,
                })
                count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                logger.error(e)
                continue
        return processes
