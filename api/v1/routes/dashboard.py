from datetime import timedelta
from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, Form, Request
from fastapi.responses import RedirectResponse
import psutil
from sqlalchemy.orm import Session
from decouple import config

from api.core.dependencies.context import add_template_context
from api.core.dependencies.flash_messages import MessageCategory, flash
from api.core.dependencies.form_builder import build_form
from api.db.database import get_db
from api.utils import paginator
from api.utils.settings import settings
from api.utils.loggers import create_logger
from api.v1.models.alert import Alert
from api.v1.models.user import User
from api.v1.services.auth import AuthService
from api.v1.services.ossec import ossec_service
from api.v1.services.system_resource import SystemResourceService
from api.v1.services.user import UserService


dashboard_router = APIRouter(prefix='/dashboard', tags=['Dashboard'])
logger = create_logger(__name__)

@dashboard_router.get('')
@add_template_context('pages/dashboard/index.html')
async def dashboard(request: Request, db: Session=Depends(get_db)):
    # Check if all services are running
    ossec_status = ossec_service.get_ossec_status()
    system_resource_usage = SystemResourceService.get_system_resource_usage()
    _, recent_alerts, _ = Alert.fetch_by_field(
        db=db,
        per_page=4,
        sort_by='timestamp',
    )
    
    if not ossec_status:
        flash(
            request=request,
            message="Ossec failed to start. Please check the logs for more information.",
            category=MessageCategory.ERROR
        )
        return RedirectResponse(url='/')
    
    alerts = [alert.to_dict() for alert in recent_alerts]
    
    return {
        "ossec_status": ossec_status,
        "system_resource_usage": system_resource_usage,
        "recent_alerts": alerts
    }
    

@dashboard_router.post("/start-ossec")
async def start_ossec(request: Request, db: Session=Depends(get_db)):
    success = ossec_service.start_ossec()
    if not success:
        flash(request, "Error starting ossec service", MessageCategory.ERROR)
    else:
        flash(request, "Ossec service started", MessageCategory.SUCCESS)
        
    return RedirectResponse(url="/dashboard", status_code=303)


@dashboard_router.post("/stop-ossec")
async def stop_ossec(request: Request, db: Session=Depends(get_db)):
    success = ossec_service.stop_ossec()
    if not success:
        flash(request, "Error stopping ossec service", MessageCategory.ERROR)
    else:
        flash(request, "Ossec service stopped", MessageCategory.SUCCESS)
        
    return RedirectResponse(url="/dashboard", status_code=303)


@dashboard_router.post("/sync-alerts")
async def sync_alerts(request: Request, db: Session=Depends(get_db)):
    success = ossec_service.sync_alerts()
    if not success:
        flash(request, "Error syncing ossec alerts", MessageCategory.ERROR)
    else:
        flash(request, "Ossec alerts synced", MessageCategory.SUCCESS)
        
    return RedirectResponse(url="/dashboard/alerts", status_code=303)


@dashboard_router.get('/alerts')
@add_template_context('pages/dashboard/alerts.html')
async def alerts(
    request: Request, 
    page: int = 1,
    per_page: int = 20,
    q: str = None,
    severity: str = None,
    db: Session=Depends(get_db),
):
    _, alerts, count = Alert.fetch_by_field(
        db=db, 
        page=page,
        per_page=per_page,
        sort_by='timestamp',
        search_fields={'description': q if q != "" else None,},
        level_text=severity if severity != "" else None
    )
    
    return paginator.build_paginated_response(
        items=[alert.to_dict() for alert in alerts],
        endpoint='/dashboard/alerts',
        page=page,
        size=per_page,
        total=count,
    )


@dashboard_router.get('/processes')
@add_template_context('pages/dashboard/processes.html')
async def processes(
    request: Request, 
    page: int = 1,
    per_page: int = 20,
    name: str = None,
    status: str = None,
):
    total_processes = len(psutil.pids())
    skip = (page - 1) * per_page
    all_processes = SystemResourceService.get_processes_info(limit=per_page, skip=skip)
    
    if name:
        all_processes = [proc for proc in all_processes if name.lower() in proc.get("name", "").lower()]
    if status:
        all_processes = [proc for proc in all_processes if proc.get("status", "").lower() == status.lower()]
        
    # system_processes = all_processes[start:end]
    
    return paginator.build_paginated_response(
        items=all_processes,
        endpoint='/dashboard/processes',
        page=page,
        size=per_page,
        total=total_processes,
    )
    

@dashboard_router.get('/files')
@add_template_context('pages/dashboard/files.html')
async def files(
    request: Request, 
    page: int = 1,
    per_page: int = 20,
    path: str = None,
    status: str = None,
):
    offset = (page - 1) * per_page
        
    all_files, total = ossec_service.get_all_monitored_files(limit=per_page, offset=offset)
    
    if path:
        all_files = [file for file in all_files if path.lower() in file.get("path", "").lower()]
    if status:
        all_files = [file for file in all_files if file.get("status", "").lower() == status.lower()]
            
    return paginator.build_paginated_response(
        items=all_files,
        endpoint='/dashboard/files',
        page=page,
        size=per_page,
        total=total,
    )
    

@dashboard_router.post("/sync-files")
async def sync_files(request: Request, db: Session=Depends(get_db)):
    success = ossec_service.sync_monitored_files()
    if not success:
        flash(request, "Error syncing monitored files", MessageCategory.ERROR)
    else:
        flash(request, "Monitored files synced", MessageCategory.SUCCESS)
        
    return RedirectResponse(url="/dashboard/files", status_code=303)
    

@dashboard_router.get('/users')
@add_template_context('pages/dashboard/users.html')
async def users(
    request: Request, 
    page: int = 1,
    per_page: int = 10,
    username: str = None,
    status: str = None,
    db: Session=Depends(get_db),
):
    if status == "active":
        is_active = True
    elif status == "inactive":
        is_active = False
    else:
        is_active = None
        
    if status == "approved":
        is_approved = True
    elif status == "unapproved":
        is_approved = False
    else:
        is_approved = None
        
    query, users, count = User.fetch_by_field(
        db=db, 
        page=page,
        per_page=per_page,
        sort_by='created_at',
        search_fields={
            'username': username if username != "" else None,
        },
        is_active=is_active,
        is_approved=is_approved
    )
    
    query = query.filter(
        User.id != request.state.current_user.id,
        User.is_admin == False
    )
    count = query.count()
    users = query.all()
    
    return paginator.build_paginated_response(
        items=[user.to_dict() for user in users],
        endpoint='/dashboard/users',
        page=page,
        size=per_page,
        total=count,
    )


# ---------------------------------------------------------------------------
# Settings routes (OSSEC config from ossec.py line 242+)
# ---------------------------------------------------------------------------

@dashboard_router.get('/settings')
@add_template_context('pages/dashboard/settings.html')
async def settings_page(request: Request):
    monitored_paths = ossec_service.get_monitored_paths()
    ignored_paths = ossec_service.get_ignored_paths()
    syscheck_tags = ["frequency", "scan_time", "scan_day", "auto_ignore", "alert_new_files", "scan_on_start", "skip_nfs"]
    global_tags = ["jsonout_output", "alerts_log", "logall", "logall_json"]
    return {
        "monitored_paths": [p.strip() for p in monitored_paths if p.strip()],
        "ignored_paths": [p.strip() for p in ignored_paths if p.strip()],
        "syscheck_frequency": ossec_service.get_syscheck_tag("frequency"),
        "syscheck_scan_time": ossec_service.get_syscheck_tag("scan_time"),
        "syscheck_scan_day": ossec_service.get_syscheck_tag("scan_day"),
        "syscheck_auto_ignore": ossec_service.get_syscheck_tag("auto_ignore"),
        "syscheck_alert_new_files": ossec_service.get_syscheck_tag("alert_new_files"),
        "syscheck_scan_on_start": ossec_service.get_syscheck_tag("scan_on_start"),
        "syscheck_skip_nfs": ossec_service.get_syscheck_tag("skip_nfs"),
        "global_jsonout_output": ossec_service.get_global_tag("jsonout_output"),
        "global_alerts_log": ossec_service.get_global_tag("alerts_log"),
        "global_logall": ossec_service.get_global_tag("logall"),
        "global_logall_json": ossec_service.get_global_tag("logall_json"),
    }


@dashboard_router.post("/settings/monitored-paths/add")
async def add_monitored_path(
    request: Request,
    path: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        ossec_service.add_monitored_path(path.strip())
        flash(request, "Monitored path added successfully", MessageCategory.SUCCESS)
    except Exception as e:
        logger.error(f"Error adding monitored path: {e}")
        flash(request, f"Error adding monitored path: {str(e)}", MessageCategory.ERROR)
    return RedirectResponse(url="/dashboard/settings", status_code=303)


@dashboard_router.post("/settings/monitored-paths/remove")
async def remove_monitored_path(
    request: Request,
    path: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        ossec_service.remove_monitored_path(path.strip())
        flash(request, "Monitored path removed successfully", MessageCategory.SUCCESS)
    except Exception as e:
        logger.error(f"Error removing monitored path: {e}")
        flash(request, f"Error removing monitored path: {str(e)}", MessageCategory.ERROR)
    return RedirectResponse(url="/dashboard/settings", status_code=303)


@dashboard_router.post("/settings/monitored-paths/attribute")
async def update_monitored_path_attribute(
    request: Request,
    path: str = Form(...),
    attr: str = Form(...),
    value: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        ossec_service.update_monitored_path_attribute(path.strip(), attr.strip(), value.strip())
        flash(request, f"Path attribute '{attr}' updated successfully", MessageCategory.SUCCESS)
    except ValueError as e:
        flash(request, str(e), MessageCategory.ERROR)
    except Exception as e:
        logger.error(f"Error updating path attribute: {e}")
        flash(request, f"Error updating path attribute: {str(e)}", MessageCategory.ERROR)
    return RedirectResponse(url="/dashboard/settings", status_code=303)


@dashboard_router.post("/settings/ignored-paths/add")
async def add_ignored_path(
    request: Request,
    path: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        ossec_service.add_ignored_path(path.strip())
        flash(request, "Ignored path added successfully", MessageCategory.SUCCESS)
    except Exception as e:
        logger.error(f"Error adding ignored path: {e}")
        flash(request, f"Error adding ignored path: {str(e)}", MessageCategory.ERROR)
    return RedirectResponse(url="/dashboard/settings", status_code=303)


@dashboard_router.post("/settings/ignored-paths/remove")
async def remove_ignored_path(
    request: Request,
    path: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        ossec_service.remove_ignored_path(path.strip())
        flash(request, "Ignored path removed successfully", MessageCategory.SUCCESS)
    except Exception as e:
        logger.error(f"Error removing ignored path: {e}")
        flash(request, f"Error removing ignored path: {str(e)}", MessageCategory.ERROR)
    return RedirectResponse(url="/dashboard/settings", status_code=303)


@dashboard_router.post("/settings/syscheck")
async def set_syscheck_setting(
    request: Request,
    tag: str = Form(...),
    value: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        ossec_service.set_syscheck_tag(tag.strip(), value.strip())
        flash(request, f"Syscheck '{tag}' updated successfully", MessageCategory.SUCCESS)
    except Exception as e:
        logger.error(f"Error setting syscheck: {e}")
        flash(request, f"Error updating syscheck: {str(e)}", MessageCategory.ERROR)
    return RedirectResponse(url="/dashboard/settings", status_code=303)


@dashboard_router.post("/settings/global")
async def set_global_setting(
    request: Request,
    tag: str = Form(...),
    value: str = Form(...),
    db: Session = Depends(get_db),
):
    try:
        ossec_service.set_global_tag(tag.strip(), value.strip())
        flash(request, f"Global setting '{tag}' updated successfully", MessageCategory.SUCCESS)
    except Exception as e:
        logger.error(f"Error setting global: {e}")
        flash(request, f"Error updating global setting: {str(e)}", MessageCategory.ERROR)
    return RedirectResponse(url="/dashboard/settings", status_code=303)
