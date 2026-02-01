from dataclasses import dataclass, asdict

@dataclass
class PasswordEntry:
    added_on: str
    algorithm: str
    ciphertext: str
    iv: str
    hmac: str
    hmac_algo: str
    encoding: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @staticmethod
    def from_dict(**kwargs) -> "PasswordEntry":
        return PasswordEntry(**kwargs)
