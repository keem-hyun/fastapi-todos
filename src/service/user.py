import bcrypt
from datetime import datetime, timedelta
from jose import jwt


class UserService:
    encoding: str = "UTF-8"
    secret_key: str = "bf6aff70a4cabdbda51015c25d1d6c3b4621b8709c70791b40f380ac4646452b"
    jwt_algorithm: str = "HS256"

    def hashed_password(self, plain_password: str) -> str:
        hashed_password: bytes = bcrypt.hashpw(
            plain_password.encode(self.encoding),
            salt=bcrypt.gensalt()
        )
        return hashed_password.decode(self.encoding)

    def verify_password(
            self, plain_password: str, hashed_password: str
    ) -> bool:
        return bcrypt.checkpw(
            plain_password.encode(self.encoding),
            hashed_password.encode(self.encoding)
        )

    def create_jwt(self, username: str) -> str:
        return jwt.encode(
            {
                "sub": username,
                "exp": datetime.now() + timedelta(days=1)
            },
            self.secret_key,
            algorithm=self.jwt_algorithm
        )
