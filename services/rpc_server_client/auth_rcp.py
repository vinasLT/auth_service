import os
import sys

import grpc

from core.logger import logger
from database.crud.user import UserService
from database.db.session import get_db
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'services', 'rpc_server_client', 'gen', 'python'))

from services.rpc_server_client.gen.python.auth.v1 import auth_pb2, auth_pb2_grpc





class AuthRcp(auth_pb2_grpc.AuthServiceServicer):
    async def GetUser(self, request: auth_pb2.GetUserRequest, context)-> auth_pb2.GetUserResponse:
        logger.debug("Received get_user rpc request")

        if not request.user_uuid:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("user_uuid is required")
            return auth_pb2.GetUserResponse()

        try:
            async with get_db() as db:
                user_service = UserService(db)
                user = await user_service.get_user_by_uuid(request.user_uuid)

                if not user:
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details("User not found")
                    return auth_pb2.GetUserResponse()

                return auth_pb2.GetUserResponse(
                    first_name=user.first_name or "",
                    last_name=user.last_name or "",
                    language=user.language or "",
                    email=user.email or "",
                    username=user.username or "",
                    phone_number=user.phone_number or "",
                    is_active=bool(user.is_active),
                    phone_verified=bool(user.phone_verified),
                    email_verified=bool(user.email_verified),
                )
        except Exception as exc:
            logger.error(f"Error while processing GetUser: {exc}")
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return auth_pb2.GetUserResponse()
