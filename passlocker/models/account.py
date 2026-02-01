from typing import Any, Literal
from dataclasses import dataclass, field

from .pw_entry import PasswordEntry
from .question import QuestionEntry

@dataclass
class Account:
    account: str
    username: str
    created_on: str
    passwords: list[PasswordEntry] = field(default_factory=list)
    active: int = 0
    type: Literal["password", "totp", "otp"] = "password"
    totp_epoch_start: int = 0
    totp_time_interval: int = 30
    totp_num_digits: int = 6
    totp_hash_algorithm: Literal["sha1", "sha256", "sha512", "md5"] = "sha1"
    notes: list[str] = field(default_factory=list)
    questions: list[QuestionEntry] = field(default_factory=list)

    # don't include PassLocker as it would form a circular dependency
    _passlocker: "PassLocker | None" = None  # noqa: F821  # pyright: ignore[reportUndefinedVariable]
 
    def to_dict(self) -> dict[str, Any]:
        # couldn't use asdict here because of the _passlocker element
        data = {
            'account': self.account,
            'username': self.username,
            'created_on': self.created_on,
            'passwords': [x.to_dict() for x in self.passwords],
            'type': self.type,
            'totp_epoch_start': self.totp_epoch_start,
            'totp_time_interval': self.totp_time_interval,
            'totp_num_digits': self.totp_num_digits,
            'totp_hash_algorithm': self.totp_hash_algorithm,
            'notes': self.notes,
            'questions': [x.to_dict() for x in self.questions]
        }
        return data

    def save(self) -> None:
        if self._passlocker is None:
            raise RuntimeError("Account is not attached to the Passlocker")
        self._passlocker._write_account(self)
    
    def delete(self) -> bool:
        if self._passlocker is None:
            raise RuntimeError("Account is not attached to the Passlocker")
        return self._passlocker.del_account(self)

    def add_password(self, password: bytes | str, encoding: str='UTF-8') -> None:
        if self._passlocker is None:
            raise RuntimeError("Account is not attached to the Passlocker")
        return self._passlocker.add_password(self, password, encoding)

    def get_active_password(self, at_time: int | None = 0) -> bytes:
        if self._passlocker is None:
            raise RuntimeError("Account is not attached to the Passlocker")
        return self._passlocker.get_active_password(self, at_time)

    def set_active_password(self, active_password: int) -> None:
        self.active = active_password
        self.save()

    def add_note(self, note: str) -> None:
        self.notes.append(note)
        self.save()
    
    def get_notes(self) -> list[str]:
        return self.notes

    def get_type(self) -> str:
        return self.type

    def change_username(self, username: str) -> None:
        _ = self.delete()
        self.username = username
        self.save()

    def change_account_name(self, account_name: str) -> None:
        _ = self.delete()
        self.account = account_name
        self.save()

    def add_question(self, question: str, answer: str):
        if self._passlocker is None:
            raise RuntimeError("Account is not attached to the Passlocker")
        return self._passlocker.add_question(self, question, answer)
    
    def list_questions(self) -> list[str]:
        return [x.question for x in self.questions]

    def get_answer(self, idx: int) -> str | None:
        if self._passlocker is None:
            raise RuntimeError("Account is not attached to the Passlocker")
        return self._passlocker.get_answer(self, idx)

    @staticmethod
    def from_dict(**kwargs) -> "Account":
        kwargs['passwords'] = [ PasswordEntry.from_dict(**x) for x in kwargs.get('passwords', []) ]
        kwargs['questions'] = [ QuestionEntry.from_dict(**x) for x in kwargs.get('questions', []) ]
        acc = Account(**kwargs)
        return acc

