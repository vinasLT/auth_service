from rfc9457 import ConflictProblem


class EmailAlreadyRegistered(ConflictProblem):
    title = "Email already registered"