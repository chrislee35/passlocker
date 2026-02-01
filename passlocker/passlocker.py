#!/usr/bin/env python3
from argon2._password_hasher import PasswordHasher
from passlocker.models.question import QuestionEntry
from passlocker.models.account import Account
from passlocker.models.pw_entry import PasswordEntry
from requests.models import Response
from base64 import b64encode as b64encode
from base64 import b64decode as b64decode
from base64 import b32decode as b32decode
import json
import sys
import os
import time
import secrets
from typing import Any, Callable, Generator, Literal
import requests
from random import randint as ri
from hashlib import sha1
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA, MD5, SHA512
from Crypto.Cipher._mode_gcm import GcmMode
# replacing PBKDF2-SHA256 with argon2
from argon2.low_level import hash_secret_raw
from argon2 import Type
xrange = range


BAD_HMAC = 1
BAD_ARGS = 2

def b64d(s: str) -> bytes:
    return b64decode(s.encode('UTF-8'))
    
def b64e(b: bytes) -> str:
    return b64encode(b).decode('UTF-8')
    
def b32d(s: str) -> bytes:
    return b32decode(s.encode('UTF-8').upper())

class PassLocker:
    ENCRYPTION_ALGORITHM: str = "aes-256-gcm"
    HMAC_ALGORITHM: str = "hmac-sha256"
    PASSLOCKER_VERSION: int = 2
    
    def __init__(self, password_cb: Callable[[str], bytes], dbdir: str | None = None, iterations: int | None = None):
        self.dbdir: str = dbdir or os.environ['HOME']+"/.passlocker"
        # I randomize the number of iterations to make lookup tables a lot harder to build
        self.iterations: int = iterations or ri(20-4, 20+4)
        if not os.path.exists(self.dbdir):
            os.mkdir(self.dbdir)
            os.chmod(self.dbdir, 0o700)
        self.unlocked: bool = False
        self.password_cb: Callable[[str], bytes] = password_cb
        self.timing: float = 0.0
        self.aes_key: bytes = b""
        self.hmac_key: bytes = b""

    def _unlock(self) -> None:
        if self.unlocked:
            return
        
        starttime = time.time()
        checkfile = "{dbdir}/.check".format(dbdir=self.dbdir)
        master_password = self.password_cb("Master password: ")

        if os.path.exists(checkfile):
            self._check_master_password(checkfile, master_password)
        else:
            self._initialize_master_password(checkfile, master_password)

        del(master_password)
        self.unlocked = True
        self.timing = time.time() - starttime

    def _check_master_password(self, checkfile: str, master_password: bytes) -> None:
        with open(checkfile, 'r') as fh:
            master: dict[str,str] = json.load(fh)  # pyright: ignore[reportAny]
        
        salt: bytes = b64d(master['salt'])
        iterations: int = int(master['iterations'])
        
        # derive from the password the master-key-decryption-key 
        # (and the password-derived hmac), decrypt the master-key (and master-hmac)
        aes_key, hmac_key, _, _ = PassLocker.make_keys(master_password, salt=salt, iterations=iterations)
        hmac: str = PassLocker.make_hmac(master_password+aes_key, hmac_key)
              
        if master['hmac'] != hmac:
            raise Exception("Master password is incorrect.")
            
        self.unlocked = True
        ciphertext: bytes = b64d(master['ciphertext'])
        iv: bytes = b64d(master['iv'])
        
        plaintext: bytes = PassLocker.decrypt(ciphertext, aes_key, iv)
        self.aes_key = plaintext[0:16]
        self.hmac_key = plaintext[16:32]

    def _create_master_key_record(self, master_password: bytes) -> dict[str, str]:
        # Take the master password, derive the master-key-encryption-key from it
        # Then encrypt the master key with the password-derived key
        # Do the same with the hmac
        aes_key, hmac_key, salt, iterations = PassLocker.make_keys(master_password, iterations=self.iterations)
        hmac = PassLocker.make_hmac(master_password+aes_key, hmac_key)
        self.aes_key = secrets.token_bytes(16)
        self.hmac_key = secrets.token_bytes(16)
        ciphertext, iv = PassLocker.encrypt(self.aes_key+self.hmac_key, aes_key)
        master = {
            'version': str(self.PASSLOCKER_VERSION),
            "algorithm" : self.ENCRYPTION_ALGORITHM,
            'salt' : b64e(salt),
            'iterations' : str(iterations),
            'hmac' : hmac, # this comes out as a hex string
            'hmac_algo': self.HMAC_ALGORITHM,
            'ciphertext' : b64e(ciphertext),
            'iv' : b64e(iv)
        }
        return master
            
    def _initialize_master_password(self, checkfile: str, master_password: bytes) -> None:
        if len(master_password) < 20:
            print("Your password is less than 20 characters.    To proceed with this week password, please type: weak password")
            ans: str = input("> ")
            if ans.strip().lower() != "weak password":
                sys.exit(0)
        
        if self.check_pwnedpasswords(master_password):
            print("This password is listed in pwnedpasswords.com.  Please try a different password.")
            raise Exception("This password is listed in pwnedpasswords.com.  Please try a different password.")
        
        verify: bytes = self.password_cb("Verify password: ")
        if verify != master_password:
            print("Passwords do not match. Bailing out.")
            sys.exit(0)
        
        master: dict[str, str] = self._create_master_key_record(master_password=master_password)
        
        with open(checkfile, 'w') as fh:
            json.dump(master, fh)
            os.chmod(checkfile, 0o600)

        self.unlocked = True

    def _b(self, input: str|bytes) -> bytes:
        if isinstance(input, str):
            return input.encode('utf-8')
        return input

    def _wrap_b(self, func) -> Callable[..., Any]:  # pyright: ignore[reportExplicitAny, reportUnknownParameterType, reportMissingParameterType]
        def wrapped_b(*args, **kwargs) -> Any:  # pyright: ignore[reportExplicitAny, reportUnknownParameterType, reportMissingParameterType, reportAny]
            return func(*args, **kwargs)  # pyright: ignore[reportUnknownVariableType]
        return wrapped_b  # pyright: ignore[reportUnknownVariableType]

    def check_pwnedpasswords(self, password: str | bytes) -> bool:
        pw: bytes = self._b(password)
        hash: str = sha1(pw).hexdigest().upper()
        prefix: str = hash[0:5]
        suffix: str = hash[5:]
        url: str = f"https://api.pwnedpasswords.com/range/{prefix}"
        with requests.Session() as session:
            req: Response = session.get(url)
            body: str = req.content.decode('UTF-8')
            for line in body.split('\n'):
                check = line.split(':',1)[0]
                if check == suffix:
                    return True
        return False

    def _to_db(self, account: str | bytes, username: str | bytes) -> str:
        acc: bytes = self._b(account)
        user: bytes = self._b(username)
        key: bytes = acc+b'|'+user
        return "%s/%s.json" % (self.dbdir, b64e(key))
        
    def get_account(self, account: str | bytes, username: str | bytes) -> Account:
        account_file: str = self._to_db(account, username)
        if not os.path.exists(account_file):
            raise Exception("Cannot find entry for %s" % account)
    
        with open(account_file, "r") as fh:
            acc_info: dict[str, Any] = json.load(fh)
        
        acc: Account = Account.from_dict(**acc_info)
        acc._passlocker = self
        return acc
        
    def _write_account(self, account: Account, overwrite: bool=True) -> None:
        account_file: str = self._to_db(account.account, account.username)
        if not overwrite and os.path.exists(account_file):
            raise Exception(f"Entry for {account.account} ({account.username}) already exists")
    
        with open(account_file, "w") as fh:
            json.dump(account.to_dict(), fh)
            os.chmod(account_file, 0o600)
        
    def _unlink_account(self, account: Account) -> None:
        account_file: str = self._to_db(account.account, account.username)
        if not os.path.exists(account_file):
            raise Exception(f"Cannot find entry for {account.account} ({account.username})")
        os.unlink(account_file)
            
    # From https://bitbucket.org/brendanlong/python-encryption/src/1737e959fa307d84a5dcf96c4139b1d91a08b2e9/encryption.py?at=master&fileviewer=file-view-default
    @staticmethod
    def make_keys(password: bytes, salt: bytes | None = None, iterations: int=20) -> tuple[bytes, bytes, bytes, int]:
        """Generates two 128-bit keys from the given password using Argon2.
             Argon2.
             password - The password.
             salt - The salt to use. If not given, a new 8-byte salt will be generated.
             iterations - The number of iterations of argon2 (default=20).

             returns (k1, k2, salt, interations)
        """
        if salt is None:
            # Generate a random 16-byte salt
            salt: bytes = secrets.token_bytes(16)

        # Generate a 32-byte (256-bit) key from the password
        key: bytes = hash_secret_raw(
            secret=password,
            salt=salt,
            time_cost=iterations,
            memory_cost=12,
            parallelism=1,
            hash_len=32,
            type=Type.I
        )

        # Split the key into two 16-byte (128-bit) keys
        return key[:16], key[16:], salt, iterations

    @staticmethod
    def make_hmac(message: bytes, key: bytes) -> str:
        """Creates an HMAC from the given message, using the given key. Uses
             HMAC-SHA256.
             message - The message to create an HMAC of.
             key - The key to use for the HMAC (at least 16 bytes).

             returns A hex string of the HMAC.
        """
        h: HMAC.HMAC = HMAC.new(key, digestmod=SHA256)
        return h.update(message).hexdigest()

    @staticmethod
    def encrypt(message: bytes, key: bytes) -> tuple[bytes, bytes]:
        """Encrypts a given message with the given key, using AES-GCM.
             message - The message to encrypt (byte string).
             key - The AES key (16 bytes).

             returns (ciphertext, iv). Both values are bytes.
        """
        # The IV should always be random
        iv: bytes = secrets.token_bytes(AES.block_size)
        cipher: GcmMode = AES.new(key, AES.MODE_GCM, iv, mac_len=16)
        ciphertext, tag = cipher.encrypt_and_digest(message)
        ciphertext += tag
        return (ciphertext, iv)

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypts a given ciphertext with the given key, using AES-GCM.
             message - The ciphertext to decrypt (byte string).
             key - The AES key (16 bytes).
             iv - The original IV used for encryption.

             returns The cleartext (byte string)
        """
        cipher: GcmMode = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=16)
        tag: bytes = ciphertext[-16:]
        ciphertext = ciphertext[0:-16]
        msg: bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return msg

    def change_master_password(self) -> None:
        self._unlock()
                
        updated_password: bytes = self.password_cb("New password: ")
        if len(updated_password) < 20:
            print("Your password is less than 20 characters.    To proceed with this week password, please type: weak password")
            ans = input("> ")
            if ans.strip().lower() != "weak password":
                sys.exit(0)
        new_password: bytes = self._b(updated_password)
            
        # Take the master password, derive the master-key-encryption-key from it
        # Then encrypt the master key with the password-derived key
        # Do the same with the hmac
        
        aes_key, hmac_key, salt, iterations = PassLocker.make_keys(new_password, iterations=self.iterations)
        hmac = PassLocker.make_hmac(new_password+aes_key, hmac_key)
        ciphertext, iv = PassLocker.encrypt(self.aes_key+self.hmac_key, aes_key)
        master = {
            "algorithm" : "aes-256-cbc",
            'salt' : b64e(salt),
            'iterations' : iterations,
            'hmac' : hmac, # this comes out as a hex string
            'ciphertext' : b64e(ciphertext),
            'iv' : b64e(iv)
        }
        checkfile = "{dbdir}/.check".format(dbdir=self.dbdir)
        with open(checkfile, 'w') as fh:
            json.dump(master, fh)
            os.chmod(checkfile, 0o600)
        
    def list_accounts(self, sep: str=' ') -> list[bytes]:
        # grab all the .json files from the dbdir and sort them by last modified
        files: list[str] = sorted(
            [ x for x in os.listdir(self.dbdir) if x.endswith(".json") ],
            key=lambda x: os.stat(self.dbdir+'/'+x).st_mtime
        )
        b64strs: list[str] = [ x.split('/')[-1][0:-5] for x in files ]
        b64decoded: list[bytes] = [ b64d(x) for x in b64strs ]
        accounts: list[bytes] = [ x.decode('UTF-8').replace('|', sep, 1).encode('UTF-8') for x in b64decoded ]
        return accounts

    def accounts(self) -> Generator[Account, None, None]:
        for filename in os.listdir(self.dbdir):
            if filename.endswith(".json"):
                basename: str = filename.split('/')[-1][0:-5]
                decoded: bytes = b64d(basename)
                account, username = decoded.split(b'|')
                acc: Account = self.get_account(account, username)
                yield acc
        
    def add_account(self, 
        account_name: str,
        username: str, 
        acc_type: Literal["password", "totp", "otp"] = "password", 
        totp_epoch_start: int = 0,
        totp_time_interval: int = 30,
        totp_num_digits: int = 6,
        totp_hash_algorithm: Literal["sha1", "sha256", "sha512", "md5"] = "sha1"
    ) -> Account:
        created_on = time.strftime("%Y-%m-%d")
        acc: Account = Account(
            account_name, username, created_on, type=acc_type
        )
        if acc_type == 'totp':
            acc.totp_epoch_start = totp_epoch_start
            acc.totp_time_interval = totp_time_interval
            acc.totp_num_digits = totp_num_digits
            acc.totp_hash_algorithm = totp_hash_algorithm
            
        self._write_account(acc, overwrite=True)
        acc._passlocker = self
        return acc
        
    def del_account(self, acc: Account):
        filename = self._to_db(acc.account, acc.username)
        if os.path.exists(filename):
            os.unlink(filename)
            return True
        else:
            return False
    
    def add_password(self, acc: Account, password: bytes | str, encoding: str='UTF-8'):
        self._unlock()
        pw: bytes = self._b(password)
            
        ciphertext, iv = PassLocker.encrypt(pw, self.aes_key)
        hmac: str = PassLocker.make_hmac(ciphertext, self.hmac_key)
    
        added_on: str = time.strftime("%Y-%m-%d")
        pw_entry: PasswordEntry = PasswordEntry(
            added_on=added_on,
            algorithm=self.ENCRYPTION_ALGORITHM,
            ciphertext=b64e(ciphertext),
            iv=b64e(iv),
            hmac=hmac,
            hmac_algo=self.HMAC_ALGORITHM,
            encoding=encoding
        )

        acc.passwords.append(pw_entry)
        if acc.type != 'otp':
            acc.active = len(acc.passwords) - 1
    
        self._write_account(acc)

    def get_active_password(self, acc: Account, at_time: int | None = 0):
        self._unlock()

        if len(acc.passwords) == 0:
            raise Exception("There is no active password for this account")
            
        if acc.active >= len(acc.passwords):
            raise Exception("All passwords on this account have been used. No valid passwords remain.")
        
        pw_entry: PasswordEntry = acc.passwords[acc.active]
        ciphertext: bytes = b64d(pw_entry.ciphertext)
        iv: bytes = b64d(pw_entry.iv)

        hmac: str = PassLocker.make_hmac(ciphertext, self.hmac_key)
        if hmac != pw_entry.hmac:
            raise Exception("HMAC verification of encrypted password failed.")
    
        output_data: bytes = PassLocker.decrypt(ciphertext, self.aes_key, iv)
        if acc.type == 'totp':
            output_data = b32d(output_data.decode('utf-8'))
            now: int | float = at_time or time.time()
            tc: int = int((now - acc.totp_epoch_start)/acc.totp_time_interval)
            tc_bytes: bytes = tc.to_bytes(8, 'big')
            ha: Literal['sha1', 'sha256', 'sha512', 'md5'] = acc.totp_hash_algorithm
            if ha == 'sha1':
                algo = SHA
            elif ha == 'md5':
                algo = MD5
            elif ha == 'sha256':
                algo = SHA256
            elif ha == 'sha512':
                algo = SHA512
            else:
                raise Exception(f'unsupported hash algorithm, {ha}. contact module author')
            # http://pike.lysator.liu.se/docs/ietf/rfc/62/rfc6238.xml
            totp_hmac: HMAC.HMAC = HMAC.new(output_data, tc_bytes, algo)
            output: bytes = totp_hmac.digest()
            offset: int = output[len(output) - 1] & 0xf;
            binary: int = ((output[offset] & 0x7f) << 24) | ((output[offset + 1] & 0xff) << 16) | ((output[offset + 2] & 0xff) << 8) | (output[offset + 3] & 0xff)
            
            output_data = str(binary)[-acc.totp_num_digits:].encode('UTF-8')
        elif acc.type == "otp":
            acc.active += 1
            self._write_account(acc)
                    
        return output_data
        
    def set_active_password(self, account: Account, active_password: int):
        account.active = active_password
        self._write_account(account)
        
    def add_otp_account(self, account_name: str, username: str, passwords: list[bytes|str]) -> Account:
        self._unlock()
        acc: Account = self.add_account(account_name, username, acc_type='otp')
        for pw in passwords:
            self.add_password(acc, pw)
        self.set_active_password(acc, 0)
        self._write_account(acc)
        return acc
        
    def add_totp_account(self, account_name: str, username: str, secret: str, 
        epoch_start: int = 0,
        time_interval: int = 30,
        num_digits: int = 6,
        hash_algorithm: Literal["sha1", "sha256", "sha512", "md5"] = "sha1") -> Account:
        
        self._unlock()
        acc: Account = self.add_account(account_name, username,
            acc_type="totp", 
            totp_epoch_start=epoch_start, 
            totp_time_interval=time_interval,
            totp_num_digits=num_digits,
            totp_hash_algorithm=hash_algorithm
        )
        self.add_password(acc, secret)
        self._write_account(acc)
        return acc
        
    def add_note(self, acc: Account, note: str) -> None:
        acc.notes.append(note)
        self._write_account(acc)
        
    def get_notes(self, acc: Account) -> list[str]:
        return acc.notes

    def get_type(self, account_name: bytes, username: bytes) -> str:
        acc: Account = self.get_account(account_name, username)
        return acc.type
        
    def change_user(self, acc: Account, to_user: str) -> None:
        # users are plain text (for now.    I might change this in the future)
        self._unlink_account(acc)
        acc.username = to_user
        self._write_account(acc)
        
    def add_question(self, acc: Account, question: str, answer: str, encoding: str = 'UTF-8'):
        self._unlock()
            
        ciphertext, iv = PassLocker.encrypt(answer.encode(encoding), self.aes_key)
        hmac = PassLocker.make_hmac(ciphertext, self.hmac_key)

        added_on: str = time.strftime("%Y-%m-%d")
        q_entry: QuestionEntry = QuestionEntry(
            added_on=added_on,
            question=question,
            algorithm=self.ENCRYPTION_ALGORITHM,
            ciphertext=b64e(ciphertext),
            iv=b64e(iv),
            hmac=hmac,
            hmac_algo=self.HMAC_ALGORITHM,
            encoding=encoding
        )
        acc.questions.append(q_entry)
        self._write_account(acc)
        
    def list_questions(self, acc: Account) -> list[str]:
        return [ x.question for x in acc.questions ]
        
    def get_answer(self, acc: Account, idx: int) -> str | None:
        if idx >= len(acc.questions):
            return None
        self._unlock()
        
        q_entry: QuestionEntry = acc.questions[idx]
        
        ciphertext = b64d(q_entry.ciphertext)
        iv = b64d(q_entry.iv)

        hmac: str = PassLocker.make_hmac(ciphertext, self.hmac_key)
        if hmac != q_entry.hmac:
            raise Exception("HMAC verification of encrypted password failed.")
    
        output_data: bytes = PassLocker.decrypt(ciphertext, self.aes_key, iv)
        answer: str = output_data.decode(q_entry.encoding)
        return answer
        
    def rename_account(self, acc: Account, new_account_name: str, new_username: str):
        self._unlink_account(acc)
        acc.account = new_account_name
        acc.username = new_username
        self._write_account(acc)
        
