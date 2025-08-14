from core.logger import logger
from custom_exceptions import EmailNotVerifiedProblem, UserDeactivatedProblem, PhoneNotVerifiedProblem
from database.models import User


def check_user(user: User, is_active: bool = True, is_email_verified: bool = True, is_phone_verified: bool = False):
    if not user.is_active and is_active:
        logger.warning(f'Action failed - account deactivated', extra={
            "email": user.email,
            "user_id": user.id,
        })
        raise UserDeactivatedProblem(detail=f"Account deactivated")

    if not user.email_verified and is_email_verified:
        logger.warning(f'Action failed - email not verified', extra={
            "email": user.email,
            "user_id": user.id,
        })
        raise EmailNotVerifiedProblem(
            detail=f"Email not verified",
            user_info={
                "user_id": user.id,
                "user_uuid": user.uuid_key,
                "email": user.email,
                "email_verified": user.email_verified
            }
        )
    if not user.phone_verified and is_phone_verified:
        logger.warning(f'Action failed - phone not verified', extra={
            "email": user.email,
            "user_id": user.id,
            "phone_number": user.phone_number,
        })
        raise PhoneNotVerifiedProblem(
            detail=f"Phone not verified",
            user_info={
                "user_id": user.id,
                "phone_number": user.phone_number,
                "phone_verified": user.phone_verified,
                "email": user.email,
                "user_uuid": user.uuid_key,
            }
        )
    return user
