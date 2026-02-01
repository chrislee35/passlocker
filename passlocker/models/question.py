from dataclasses import dataclass, asdict

@dataclass
class QuestionEntry:
    added_on: str
    question: str
    algorithm: str
    ciphertext: str
    iv: str
    hmac: str
    hmac_algo: str
    encoding: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @staticmethod
    def from_dict(**kwargs) -> "QuestionEntry":
        return QuestionEntry(**kwargs)
