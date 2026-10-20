
import logging
import logging.config
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError
from services.seed import seed_system_data
from db.postgres import async_session
from api.v1 import auth, roles, users
from core.config import config
from core.logger import LOGGING
from db import postgres, redis
from services.custom_exception import (
    InvalidCredentialsError,
    PermissionNotFoundError,
    RoleAlreadyExistsError,
    RoleNotFoundError,
    TokenError,
    UserAlreadyExistsError,
    UserNotFoundError,
)

logging.config.dictConfig(LOGGING)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Управление жизненным циклом приложения."""
    logger.info('Запуск приложения %s...', config.PROJECT_NAME)

    redis.init_redis()

    try:
        await postgres.check_postgres()
        logger.info('PostgreSQL доступен')
    except Exception as exc:
        logger.exception('PostgreSQL недоступен при старте')
        raise RuntimeError('PostgreSQL unavailable at startup') from exc

    try:
        await redis.get_redis().ping()
        logger.info('Redis доступен')
    except Exception as exc:
        logger.exception('Redis недоступен при старте')
        raise RuntimeError('Redis unavailable at startup') from exc

    try:
        async with async_session() as session:
            await seed_system_data(session)
        logger.info('Системные роли и права инициализированы')
    except Exception as exc:
        logger.exception('Ошибка инициализации системных ролей и прав')
        raise RuntimeError('Failed to seed system roles and permissions') from exc

    logger.info('Приложение запущено')

    try:
        yield
    finally:
        logger.info('Остановка приложения')

        try:
            await redis.close_redis()
        except Exception as exc:
            logger.error('Ошибка при закрытии Redis: %s', exc)

        try:
            await postgres.close_postgres()
        except Exception as exc:
            logger.error('Ошибка при закрытии PostgreSQL: %s', exc)

app = FastAPI(
    title=config.PROJECT_NAME,
    version='1.0.0',
    docs_url='/api/v1/auth/docs',
    redoc_url='/api/v1/auth/redoc',
    openapi_url='/api/v1/auth/openapi.json',
    lifespan=lifespan,
)

# --- обработчики исключений ---


@app.exception_handler(UserAlreadyExistsError)
async def user_exists_handler(request: Request, exc: UserAlreadyExistsError):
    return JSONResponse(
        status_code=409,
        content={'detail': str(exc)},
    )


@app.exception_handler(InvalidCredentialsError)
async def invalid_credentials_handler(request: Request, exc: InvalidCredentialsError):
    return JSONResponse(
        status_code=401,
        content={'detail': str(exc)},
    )


@app.exception_handler(UserNotFoundError)
async def user_not_found_handler(request: Request, exc: UserNotFoundError):
    return JSONResponse(
        status_code=404,
        content={'detail': str(exc)},
    )


@app.exception_handler(TokenError)
async def token_error_handler(request: Request, exc: TokenError):
    return JSONResponse(
        status_code=401,
        content={'detail': str(exc)},
    )


@app.exception_handler(RoleAlreadyExistsError)
async def role_exists_handler(request: Request, exc: RoleAlreadyExistsError):
    return JSONResponse(
        status_code=409,
        content={'detail': str(exc)},
    )


@app.exception_handler(RoleNotFoundError)
async def role_not_found_handler(request: Request, exc: RoleNotFoundError):
    return JSONResponse(
        status_code=404,
        content={'detail': str(exc)},
    )


@app.exception_handler(PermissionNotFoundError)
async def perm_not_found_handler(request: Request, exc: PermissionNotFoundError):
    return JSONResponse(
        status_code=404,
        content={'detail': str(exc)},
    )


@app.exception_handler(RedisError)
@app.exception_handler(SQLAlchemyError)
async def storage_unavailable_handler(request: Request, exc: Exception):
    logger.exception('Хранилище недоступно: %s', exc)
    return JSONResponse(
        status_code=503,
        content={'detail': 'Сервис временно недоступен. Попробуйте позднее.'},
    )


app.include_router(auth.router, prefix='/api/v1')
app.include_router(users.router, prefix='/api/v1')
app.include_router(roles.router, prefix='/api/v1')
