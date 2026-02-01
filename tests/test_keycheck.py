import sys
sys.path.append('.')

from passlocker.models.account import Account
from passlocker.passlocker import PassLocker

def get_master_pw(prompt: str) -> bytes:
    return "mastermastermastermaster098345729834765938".encode('UTF-8')


def test_regular_password():
    pl: PassLocker = PassLocker(get_master_pw, iterations=10, dbdir='tests/db/') # for testing
    acc: Account = pl.get_account("test", "chris")
    print(acc.get_active_password().decode('utf-8'))

test_regular_password()