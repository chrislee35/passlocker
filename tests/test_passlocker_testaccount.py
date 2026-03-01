import sys
sys.path.append('.')
import getpass

from passlocker.models.account import Account
from passlocker.passlocker import PassLocker

def get_master_password(prompt: str) -> bytes:
    return getpass.getpass(prompt=prompt).encode('UTF-8')

pl: PassLocker = PassLocker(get_master_password) # for testing
acc: Account = pl.get_account("passlocker", "testaccount")
print(acc.get_active_password().decode('utf-8'))
