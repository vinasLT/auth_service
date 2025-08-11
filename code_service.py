class CodeService:
    CODE_LENGTH = 6
    CODE_EXPIRY_MINUTES = 10

    def __init__(self, user_uuid: str):
        self.user_uuid = user_uuid

    @classmethod
    def generate_code(cls)->str:
        import random
        return ''.join(random.choices('0123456789', k=cls.CODE_LENGTH))



