from typing import override
import unittest
import os
import glob
from base64 import b32encode
from passlocker.models.account import Account
from passlocker.passlocker import PassLocker


class PassLockerTest(unittest.TestCase):
    @override
    def setUp(self):
        for acc in glob.glob("tests/db/*.json"):
            os.unlink(acc)
        if os.path.exists("tests/db/.check"):
            os.unlink("tests/db/.check")

    @override
    def tearDown(self):
        for acc in glob.glob("tests/db/*.json"):
            os.unlink(acc)
        if os.path.exists("tests/db/.check"):
            os.unlink("tests/db/.check")

    def get_master_pw(
        self, prompt: str
    ) -> bytes:  # pyright: ignore[reportUnusedParameter]
        return "mastermastermastermaster098345729834765938".encode("UTF-8")

    def get_pwned_pw(
        self, prompt: str
    ) -> bytes:  # pyright: ignore[reportUnusedParameter]
        return "passwordpassword123456".encode("UTF-8")

    def test_pwned_password(self):
        with self.assertRaises(Exception):
            pl: PassLocker = PassLocker(
                self.get_pwned_pw, iterations=10, dbdir="tests/db/"
            )  # for testing
            acc: Account = pl.add_account("test", "chris")
            acc.add_password(b"password")

    def test_regular_password(self):
        pl: PassLocker = PassLocker(
            self.get_master_pw, iterations=10, dbdir="tests/db/"
        )  # for testing
        acc: Account = pl.add_account("test", "chris")
        acc.add_password(b"password")
        self.assertEqual("password", acc.get_active_password().decode("utf-8"))

    def test_otp(self):
        pl = PassLocker(
            self.get_master_pw, iterations=10, dbdir="tests/db/"
        )  # for testing
        acc: Account = pl.add_otp_account(
            "otp_test", "chris", [b"a", b"b", b"c", b"d", b"e", b"f"]
        )
        self.assertEqual("a", acc.get_active_password().decode("utf-8"))
        self.assertEqual("b", acc.get_active_password().decode("utf-8"))
        self.assertEqual("c", acc.get_active_password().decode("utf-8"))
        self.assertEqual("d", acc.get_active_password().decode("utf-8"))
        self.assertEqual("e", acc.get_active_password().decode("utf-8"))
        self.assertEqual("f", acc.get_active_password().decode("utf-8"))
        with self.assertRaisesRegex(
            Exception,
            "All passwords on this account have been used. No valid passwords remain.",
        ):
            _ = acc.get_active_password()

    def make_test_totp_key(self, length: int):
        return b32encode(
            "".join([str((x + 1) % 10) for x in range(length)]).encode("ASCII")
        ).decode("ASCII")

    def test_totp(self):
        pl: PassLocker = PassLocker(
            self.get_master_pw, iterations=10, dbdir="tests/db/"
        )  # for testing

        test_vectors: list[tuple[int, str, str]] = [
            (59, "94287082", "sha1"),
            (59, "46119246", "sha256"),
            (59, "90693936", "sha512"),
            (1111111109, "07081804", "sha1"),
            (1111111109, "68084774", "sha256"),
            (1111111109, "25091201", "sha512"),
            (1111111111, "14050471", "sha1"),
            (1111111111, "67062674", "sha256"),
            (1111111111, "99943326", "sha512"),
            (1234567890, "89005924", "sha1"),
            (1234567890, "91819424", "sha256"),
            (1234567890, "93441116", "sha512"),
            (2000000000, "69279037", "sha1"),
            (2000000000, "90698825", "sha256"),
            (2000000000, "38618901", "sha512"),
            (20000000000, "65353130", "sha1"),
            (20000000000, "77737706", "sha256"),
            (20000000000, "47863826", "sha512"),
        ]

        sha1_key = self.make_test_totp_key(20)
        sha256_key = self.make_test_totp_key(32)
        sha512_key = self.make_test_totp_key(64)
        accounts: dict[str, Account] = {}
        accounts["sha1"] = pl.add_totp_account(
            "totp_test_sha1",
            "chris",
            sha1_key,
            num_digits=8,
            time_interval=30,
            hash_algorithm="sha1",
        )
        accounts["sha256"] = pl.add_totp_account(
            "totp_test_sha256",
            "chris",
            sha256_key,
            num_digits=8,
            time_interval=30,
            hash_algorithm="sha256",
        )
        accounts["sha512"] = pl.add_totp_account(
            "totp_test_sha512",
            "chris",
            sha512_key,
            num_digits=8,
            time_interval=30,
            hash_algorithm="sha512",
        )
        for tv in test_vectors:
            result = accounts[tv[2]].get_active_password(at_time=tv[0]).decode("utf-8")
            self.assertEqual(tv[1], result)

    def test_utf8(self):
        # pl1: Passlocker = PassLocker(lambda x: "生麦生米生卵生麦生米生卵生麦生米生卵".encode('UTF-8'), iterations=10, dbdir='db/') # for testing
        pl2: PassLocker = PassLocker(
            lambda x: "生麦生米生卵生麦生米生卵生麦生米生卵".encode("UTF-8"),
            iterations=10,
            dbdir="tests/db/",
        )  # for testing
        acc: Account = pl2.add_account("テスト", "クリス")
        acc.add_password("マジで？ホンマに？何でやねん？")
        self.assertEqual(
            "マジで？ホンマに？何でやねん？", acc.get_active_password().decode("utf-8")
        )

    def test_username(self):
        pl: PassLocker = PassLocker(
            self.get_master_pw, iterations=10, dbdir="tests/db/"
        )  # for testing
        acc: Account = pl.add_account("test", "chris")
        self.assertEqual("chris", acc.username)
        acc.change_username("bill")
        self.assertEqual("bill", acc.username)

    def test_questions(self):
        pl: PassLocker = PassLocker(
            self.get_master_pw, iterations=10, dbdir="tests/db/"
        )  # for testing
        acc: Account = pl.add_account("test", "chris")
        acc.add_question("name of dog", "jack")
        acc.add_question("name of cat", "pantsalot")
        acc.add_question("city of first kiss", "mossville")
        answer: list[str] = ["name of dog", "name of cat", "city of first kiss"]
        self.assertEqual(answer, acc.list_questions())
        self.assertEqual("jack", acc.get_answer(0))
        self.assertEqual("pantsalot", acc.get_answer(1))
        self.assertEqual("mossville", acc.get_answer(2))

    def test_notes(self):
        pl: PassLocker = PassLocker(
            self.get_master_pw, iterations=10, dbdir="tests/db/"
        )  # for testing
        acc: Account = pl.add_account("test", "chris")
        acc.add_note("this is a note")
        acc.add_note("this is another note")
        answer: list[str] = ["this is a note", "this is another note"]
        self.assertEqual(answer, acc.get_notes())


if __name__ == "__main__":
    unittest.main()
