import uuid

from rfc9457 import ServerProblem
from sqlalchemy.exc import IntegrityError, MultipleResultsFound
from sqlalchemy.ext.asyncio import AsyncSession

from core.logger import logger
from custom_exceptions import RegisteredWithPresentCredentialsProblem
from database.crud.many_to_many.user_role import UserRoleService
from database.crud.role import RoleService
from database.crud.user import UserService
from database.models import User
from database.schemas.many_to_many.user_role import UserRoleCreate
from database.schemas.user import UserCreate
from schemas.request_schemas.registration import UserIn


async def create_or_update_user(
    db: AsyncSession,
    user_data: UserIn,
    password_hash: str,
    *,
    mark_verified: bool = False,
    log_context: str = "Registration",
    is_created_manually: bool = False,
) -> User:
    user_service = UserService(db)
    role_service = RoleService(db)
    user_role_service = UserRoleService(db)

    email_value = str(user_data.email)
    phone_value = user_data.phone_number

    try:
        by_email = await user_service.get_by_email(email_value)
        by_phone = await user_service.get_by_phone_number(phone_value)
        logger.debug(
            "Checking for existing credentials",
            extra={"email": by_email, "phone_number": by_phone},
        )
    except MultipleResultsFound:
        logger.error(
            f"{log_context} failed - multiple results found",
            extra={"email": email_value, "phone_number": phone_value},
        )
        raise ServerProblem(detail="Multiple results found for email or phone number")

    if by_email and getattr(by_email, "email_verified", False):
        logger.warning(
            f"{log_context} failed - email verified",
            extra={"email": email_value, "user_id": by_email.id},
        )
        raise RegisteredWithPresentCredentialsProblem(detail="Email already registered and verified")

    if by_phone and getattr(by_phone, "phone_verified", False):
        logger.warning(
            f"{log_context} failed - phone verified",
            extra={"phone_number": phone_value, "user_id": by_phone.id},
        )
        raise RegisteredWithPresentCredentialsProblem(detail="Phone number already registered and verified")

    if by_email:
        if by_phone and by_phone.id != by_email.id:
            by_phone.phone_number = ""
            await db.flush()
        by_email.phone_number = phone_value
        by_email.first_name = user_data.first_name
        by_email.last_name = user_data.last_name
        by_email.password_hash = password_hash
        if mark_verified:
            by_email.email_verified = True
            by_email.phone_verified = True
        try:
            await db.commit()
            await db.refresh(by_email)
        except IntegrityError as ie:
            await db.rollback()
            logger.error(
                "Integrity error on update (email branch)",
                extra={"email": email_value, "phone_number": phone_value, "error": str(ie)},
            )
            raise RegisteredWithPresentCredentialsProblem(detail="Email or phone number already registered")
        logger.info(
            f"Updated unverified user by email ({log_context})",
            extra={"user_id": by_email.id, "uuid": by_email.uuid_key},
        )
        return by_email

    if by_phone:
        by_phone.email = email_value
        by_phone.username = email_value.split("@")[0]
        by_phone.first_name = user_data.first_name
        by_phone.last_name = user_data.last_name
        by_phone.password_hash = password_hash
        if mark_verified:
            by_phone.email_verified = True
            by_phone.phone_verified = True
        try:
            await db.commit()
            await db.refresh(by_phone)
        except IntegrityError as ie:
            await db.rollback()
            logger.error(
                "Integrity error on update (phone branch)",
                extra={"email": email_value, "phone_number": phone_value, "error": str(ie)},
            )
            raise RegisteredWithPresentCredentialsProblem(detail="Email or phone number already registered")
        logger.info(
            f"Updated unverified user by phone ({log_context})",
            extra={"user_id": by_phone.id, "uuid": by_phone.uuid_key},
        )
        return by_phone

    default_role = await role_service.get_default_role()
    user_uuid = str(uuid.uuid4())

    new_user_data = UserCreate(
        uuid_key=user_uuid,
        password_hash=password_hash,
        email=user_data.email,
        phone_number=phone_value,
        username=email_value.split("@")[0],
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        email_verified=mark_verified,
        phone_verified=mark_verified,
        is_created_manually=is_created_manually,
    )

    try:
        user = await user_service.create(new_user_data, flush=True)
        await user_role_service.create(UserRoleCreate(user_id=user.id, role_id=default_role.id))
        await db.commit()
        await db.refresh(user)
    except IntegrityError as ie:
        await db.rollback()
        logger.error(
            "Integrity error on create",
            extra={"email": email_value, "phone_number": phone_value, "error": str(ie)},
        )
        raise RegisteredWithPresentCredentialsProblem(detail="Email or phone number already registered")

    logger.info(f"{log_context} successful", extra={"user_id": user.id, "uuid": user_uuid})
    return user
