from rfc9457 import ConflictProblem, Problem, UnauthorisedProblem
from fastapi import Request, Response

class RegisteredWithPresentCredentialsProblem(ConflictProblem):
    title = "User already registered with present credentials"

class TooManyRequests(Problem):
    status = 429
    title = "Too many requests, try after "
    detail = "Too many requests"

async def raise_rate_limiter_error(request: Request, response: Response, pexpire: int):
    raise TooManyRequests(
        title="Too many requests",
        detail=f"Too many requests, try after {pexpire // 1000} seconds"
    )

class EmailNotVerifiedProblem(UnauthorisedProblem):
    type = "email-not-verified"
    title = "Email not verified"