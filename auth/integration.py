"""One-line installer that wires the auth module into a FastAPI app.

Usage in agent_server.py (one import + one call — no other changes):

    from fastapi import FastAPI
    from auth.integration import install_auth

    app = FastAPI()
    # ... existing ARGUS setup ...
    install_auth(app)

This:
  1. Creates auth tables if missing (idempotent).
  2. Bootstraps the first OWNER if none exists + env vars permit.
  3. Mounts /auth/* and /scim/v2/* routers.
  4. Adds a startup task that periodically:
       - sweeps expired sessions
       - enforces audit retention
  5. Adds a /healthz check that includes auth-db reachability.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger("argus.auth.integration")


def install_auth(app: Any) -> None:
    """Mount the auth module on a FastAPI (or compatible) app instance.

    Idempotent — safe to call multiple times.
    """
    if getattr(app, "_argus_auth_installed", False):
        logger.info("auth: install_auth already called; skipping")
        return
    setattr(app, "_argus_auth_installed", True)

    # 1. Schema + bootstrap (synchronous, runs once)
    from auth.db import init_db
    from auth.bootstrap import maybe_auto_bootstrap

    try:
        init_db()
        maybe_auto_bootstrap()
    except Exception as e:
        # Don't crash the host app — auth issues should be loud but recoverable
        logger.exception("auth: bootstrap failed: %s", e)

    # 2. Mount routers
    try:
        from auth.routes import router as auth_router
        from auth.scim import router as scim_router
        app.include_router(auth_router)
        app.include_router(scim_router)
    except Exception as e:
        logger.exception("auth: router mount failed: %s", e)
        raise

    # 3. Periodic housekeeping — sessions + audit retention
    @app.on_event("startup")          # type: ignore[misc]
    async def _start_auth_housekeeping():
        asyncio.create_task(_housekeeping_loop())

    # 4. Health endpoint
    try:
        from sqlalchemy import text
        from auth.db import SessionLocal

        @app.get("/healthz/auth", tags=["healthz"])
        def _healthz_auth():
            db = SessionLocal()
            try:
                db.execute(text("SELECT 1"))
                return {"ok": True}
            finally:
                db.close()
    except Exception:
        pass

    logger.info("auth: installed /auth/* and /scim/v2/* routers + housekeeping")


async def _housekeeping_loop():
    """Background loop:
       • every 5 min sweep expired sessions
       • every 60 min enforce audit retention
    """
    from auth.audit import enforce_retention
    from auth.db import SessionLocal
    from auth.sessions import sweep_expired

    last_retention = 0.0
    while True:
        try:
            db = SessionLocal()
            try:
                sweep_expired(db)
            finally:
                db.close()

            now = asyncio.get_event_loop().time()
            if now - last_retention > 3600:
                enforce_retention()
                last_retention = now
        except Exception as e:
            logger.warning("auth housekeeping iteration failed: %s", e)

        await asyncio.sleep(300)        # 5 min


__all__ = ["install_auth"]
