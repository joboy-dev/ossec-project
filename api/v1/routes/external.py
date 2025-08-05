from fastapi import APIRouter, Request
from api.core.dependencies.context import add_template_context
from api.utils.loggers import create_logger


external_router = APIRouter(tags=["External"])
logger = create_logger(__name__)

@external_router.get("/")
@add_template_context('pages/index.html')
async def index(request: Request) -> dict:
    features = [
        {
            'title': 'File Integrity Monitoring',
            'description': 'SHA-256 hashing of critical system files with baseline comparison to detect unauthorized modifications.',
            'benefits': [
                '/etc/passwd, /etc/ssh/sshd_config monitoring',
                'Periodic baseline verification',
                'Tamper detection alerts'
            ],
            'icon': 'fa fa-file-alt text-accent-success'
        },
        {
            'title': 'Process Monitoring',
            'description': 'Real-time tracking and whitelist validation of system processes with resource usage analysis.',
            'benefits': [
                'Dynamic whitelist comparison',
                'CPU/memory usage tracking',
                'Suspicious process detection'
            ],
            'icon': 'fa fa-cogs text-accent-info'
        },
        {
            'title': 'Log Analysis',
            'description': 'Rule-based filtering and signature detection for identifying suspicious activities and known threats.',
            'benefits': [
                '/var/log/auth.log parsing',
                'Failed login attempt detection',
                'Privilege escalation alerts'
            ],
            'icon': 'fa fa-eye text-accent-warning'
        }
    ]
    return {
        'features': features
    }