
from typing import Optional
from uuid import UUID

from models.auth_models import Permission, Role, RolePermission, UserRole
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from db_work.abc_rbac import RBACRepository


class PostgresRBACRepository(RBACRepository):
    """Работа с таблицами auth.roles, auth.permissions, auth.user_roles, auth.role_permissions."""

    def __init__(self, session: AsyncSession):
        self._session = session

    # --- Роли ---

    async def get_role_by_name(self, name: str) -> Optional[Role]:
        stmt = select(Role).where(Role.name == name)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def create_role(
        self,
        name: str,
        description: str | None,
        permissions: list[Permission] | None = None
    ) -> Role:
        """Создает новую роль и связывает её с правами."""
        role = Role(name=name, description=description)


        if permissions:
            role.permissions.extend(permissions)

        self._session.add(role)
        await self._session.flush()
        await self._session.commit()
        await self._session.refresh(role)

        return role

    async def delete_role(self, role_id: UUID) -> bool:

        role = await self._session.get(Role, role_id)
        if role is None:
            return False

        await self._session.delete(role)
        await self._session.commit()
        return True

    async def list_roles(self) -> list[Role]:
        stmt = select(Role).options(joinedload(Role.permissions))
        result = await self._session.execute(stmt)
        return list(result.unique().scalars().all())

    # Назначение ролей

    async def assign_role_to_user(self, user_id: UUID, role_id: UUID) -> None:
        # Проверяем, нет ли уже такой связи
        stmt = select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id
        )
        existing = await self._session.execute(stmt)
        if existing.scalars().first():
            return

        link = UserRole(user_id=user_id, role_id=role_id)
        self._session.add(link)
        await self._session.commit()

    async def remove_role_from_user(self, user_id: UUID, role_id: UUID) -> None:
        stmt = delete(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role_id
        )
        await self._session.execute(stmt)
        await self._session.commit()

    async def get_user_roles(self, user_id: UUID) -> list[Role]:
        stmt = (
            select(Role)
            .join(UserRole, Role.id == UserRole.role_id)
            .where(UserRole.user_id == user_id)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    # --- Разрешения ---

    async def get_permission_by_codename(self, codename: str) -> Optional[Permission]:
        stmt = select(Permission).where(Permission.codename == codename)
        result = await self._session.execute(stmt)
        return result.scalars().first()

    async def add_permission_to_role(self, role_id: UUID, permission_id: UUID) -> None:
        stmt = select(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id
        )
        existing = await self._session.execute(stmt)
        if existing.scalars().first():
            return

        link = RolePermission(role_id=role_id, permission_id=permission_id)
        self._session.add(link)
        await self._session.commit()

    async def remove_permission_from_role(self, role_id: UUID, permission_id: UUID) -> None:
        stmt = delete(RolePermission).where(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id
        )
        await self._session.execute(stmt)
        await self._session.commit()

    async def get_user_permissions(self, user_id: UUID) -> set[str]:
        """
        Получает все разрешения пользователя.
        Запрос: Users -> User_Roles -> Roles -> Role_Permissions -> Permissions
        """
        stmt = (
            select(Permission.codename)
            .join(RolePermission, Permission.id == RolePermission.permission_id)
            .join(Role, RolePermission.role_id == Role.id)
            .join(UserRole, Role.id == UserRole.role_id)
            .where(UserRole.user_id == user_id)
            .distinct()
        )
        result = await self._session.execute(stmt)
        return set(result.scalars().all())
