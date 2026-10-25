"""Friendly error responses with correlated operational logs."""
import json
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import re
from uuid import uuid4
from urllib.parse import parse_qs

from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

LOGGER = logging.getLogger('daksh.api.errors')
CODE = re.compile(r'^[a-f0-9]{32}$')
MESSAGES = {
    400: 'The request could not be accepted. Check your selections and try again.',
    401: 'Your session has expired. Sign in again.',
    403: 'You do not have permission to perform this action.',
    404: 'The requested item could not be found. Refresh the page and try again.',
    409: 'This action is not available in the current state. Refresh the page and try again.',
    410: 'The saved data is no longer available.',
    413: 'The upload is too large. Choose a smaller file.',
    422: 'Some settings are invalid. Check the fields and try again.',
    429: 'Too many requests. Wait a moment and try again.',
    500: 'Something went wrong while processing the request. Please try again.',
    502: 'The backend is temporarily unavailable. Please try again shortly.',
    503: 'The backend is temporarily unavailable. Please try again shortly.',
    504: 'The backend took too long to respond. Please try again.',
}
SAFE_DETAILS = {
    'queue_edit_unavailable': 'This scan is already being edited, has started, was deleted, or its edit reservation expired. Return to Queued Scans and reopen it before editing.',
    'invalid_credentials': 'The username or password is incorrect.',
    'password_change_required': 'Change your password before continuing.',
    'admin_required': 'Administrator access is required for this action.',
    'username_taken': 'That username is already in use.',
    'cannot_delete_self': 'You cannot delete your own account.',
    'cannot_delete_last_admin': 'Keep at least one administrator account.',
    'target_not_directory': 'Choose a directory to scan.',
    'target_outside_allowed_roots': 'Choose a directory within the configured scan locations.',
    'scan_not_active': 'This scan has already finished.',
    'effort_requires_finished_scan': 'Wait until the scan finishes before calculating effort.',
}


def log_error(code, method, path, status, detail, exc_info=None):
    LOGGER.error(json.dumps(dict(error_code=code, method=method, path=path,
                                status=status, detail=detail), ensure_ascii=True, default=str), exc_info=exc_info)


def error_response(status, code, detail=None, headers=None):
    message = SAFE_DETAILS.get(detail) if isinstance(detail, str) else None
    payload = dict(detail=message or MESSAGES.get(status, MESSAGES[500]), error_code=code)
    return JSONResponse(payload, status_code=status, headers={**(headers or {}), 'X-Request-ID': code})


class ErrorReferences:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        supplied = dict(scope.get('headers', [])).get(b'x-request-id', b'').decode('ascii', errors='ignore')
        if not CODE.fullmatch(supplied):
            supplied = parse_qs(scope.get('query_string', b'').decode('ascii', errors='ignore')).get('request_id', [''])[0]
        code = supplied if CODE.fullmatch(supplied) else uuid4().hex
        scope.setdefault('state', {})['error_code'] = code
        started = False
        async def tagged_send(message):
            nonlocal started
            if message['type'] == 'http.response.start':
                started = True
                headers = [(k,v) for k,v in message.get('headers', []) if k.lower() != b'x-request-id']
                message = dict(message, headers=headers + [(b'x-request-id', code.encode())])
            await send(message)
        try:
            await self.app(scope, receive, tagged_send)
        except Exception as exc:
            log_error(code, scope['method'], scope['path'], 500, str(exc), exc_info=True)
            if started:
                raise
            await error_response(500, code)(scope, receive, tagged_send)


def install_error_handling(app, log_path=None):
    if not LOGGER.handlers:
        LOGGER.setLevel(logging.ERROR)
        LOGGER.propagate = False
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        LOGGER.addHandler(handler)
    if log_path and not any(isinstance(h, RotatingFileHandler) for h in LOGGER.handlers):
        path = Path(log_path); path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(path, maxBytes=10 * 1024 * 1024, backupCount=3, encoding='utf-8')
        handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))
        LOGGER.addHandler(handler)
    app.add_middleware(ErrorReferences)

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        code = request.state.error_code
        cause = exc.__cause__ or exc.__context__
        trace = (type(cause), cause, cause.__traceback__) if cause and exc.status_code >= 500 else None
        log_error(code, request.method, request.url.path, exc.status_code, exc.detail, exc_info=trace)
        return error_response(exc.status_code, code, exc.detail, exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        code = request.state.error_code
        # Validation errors may contain passwords in input. Log field and type,
        # never the submitted values or request body.
        detail = [dict(field=error['loc'], type=error['type'], message=error['msg']) for error in exc.errors()]
        log_error(code, request.method, request.url.path, 422, detail)
        return error_response(422, code)


from pydantic import BaseModel, Field
from typing import Literal

class ClientErrorReport(BaseModel):
    error_code: str = Field(pattern=r'^[a-f0-9]{32}$')
    path: str = Field(max_length=512, pattern=r'^/api/')
    method: Literal['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] = 'GET'
    detail: str = Field(max_length=1000)
    time: int


def record_client_error(payload):
    log_error(payload.error_code, payload.method, payload.path.split('?')[0], 0,
              dict(client_reported=True, client_time=payload.time, transport_error=payload.detail))
