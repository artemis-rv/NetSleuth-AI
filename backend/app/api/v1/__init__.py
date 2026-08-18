"""
backend/app/api/v1/__init__.py
------------------------------
V1 API Router registry for NetSleuth-AI.

Aggregates all 15 versioned domain routers into a single v1_router.
"""

from fastapi import APIRouter

from app.auth.router import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.cases import router as cases_router
from app.api.v1.acquisitions import router as acquisitions_router
from app.api.v1.analysis import router as analysis_router
from app.api.v1.findings import router as findings_router
from app.api.v1.network import router as network_router
from app.api.v1.timeline import router as timeline_router
from app.api.v1.graph import router as graph_router
from app.api.v1.mitre import router as mitre_router
from app.api.v1.evidence import router as evidence_router
from app.api.v1.custody import router as custody_router
from app.api.v1.reports import router as reports_router
from app.api.v1.copilot import router as copilot_router
from app.api.v1.admin import router as admin_router

v1_router = APIRouter(prefix="/v1")

# Register all domain routers
v1_router.include_router(auth_router)
v1_router.include_router(users_router)
v1_router.include_router(cases_router)
v1_router.include_router(acquisitions_router)
v1_router.include_router(analysis_router)
v1_router.include_router(findings_router)
v1_router.include_router(network_router)
v1_router.include_router(timeline_router)
v1_router.include_router(graph_router)
v1_router.include_router(mitre_router)
v1_router.include_router(evidence_router)
v1_router.include_router(custody_router)
v1_router.include_router(reports_router)
v1_router.include_router(copilot_router)
v1_router.include_router(admin_router)

__all__ = [
    "v1_router",
    "auth_router",
    "users_router",
    "cases_router",
    "acquisitions_router",
    "analysis_router",
    "findings_router",
    "network_router",
    "timeline_router",
    "graph_router",
    "mitre_router",
    "evidence_router",
    "custody_router",
    "reports_router",
    "copilot_router",
    "admin_router",
]
