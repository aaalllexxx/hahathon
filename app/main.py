from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.dashboard.routes import apply_stored_settings, router as dashboard_router
from app.database import SessionLocal, init_db
from app.webhooks.gitlab import router as gitlab_webhook_router
from app.webhooks.precheck import router as precheck_router


def configure_logging() -> None:
    logging.basicConfig(
        level=settings.LOG_LEVEL,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def create_app() -> FastAPI:
    configure_logging()
    app = FastAPI(title=settings.APP_NAME, version="0.1.0")
    app.mount("/static", StaticFiles(directory="app/static"), name="static")
    app.include_router(dashboard_router)
    app.include_router(gitlab_webhook_router)
    app.include_router(precheck_router)

    @app.on_event("startup")
    def on_startup() -> None:
        init_db()
        db = SessionLocal()
        try:
            apply_stored_settings(db)
        finally:
            db.close()

    return app


app = create_app()
