#!/usr/bin/env python3
from base64 import b64encode as b64encode
from base64 import b64decode as b64decode
from base64 import b32decode as b32decode
import json
import sys
import os
import time
import secrets
import requests
from random import randint as ri
from hashlib import sha1

xrange = range

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA256, SHA, MD5, SHA512
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    print("Error: PyCrypto is not installed. You should be able to install it with pip. On Fedora and Ubuntu, the pip package is called python3-pip, so you should be able to run:\n    sudo apt-get install python3-pip # if you have Ubuntu\n    sudo yum install python3-pip # if you have Fedora\n    sudo python3-pip install pycrypto")
    sys.exit(1)

BAD_HMAC = 1
BAD_ARGS = 2

def b64d(s):
    return b64decode(s.encode('UTF-8'))
    
def b64e(b):
    return b64encode(b).decode('UTF-8')
    
def b32d(s):
    return b32decode(s.encode('UTF-8').upper())

class PassLocker:
    def __init__(self, password_cb, **kwargs):
        self.dbdir = kwargs.get('dbdir', os.environ['HOME']+"/.passlocker")
        # I randomize the number of iterations to make lookup tables a lot harder to build
        self.iterations = kwargs.get('iterations', ri(100000-100, 100000+100))
        if not os.path.exists(self.dbdir):
            os.mkdir(self.dbdir)
            os.chmod(self.dbdir, 0o700)
        self.unlocked = False
        self.password_cb = password_cb

    def _unlock(self):
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

    def _check_master_password(self, checkfile, master_password):
        with open(checkfile, 'r') as fh:
            master = json.load(fh)
        
        salt = b64d(master['salt'])
        iterations = master['iterations']
        
        # derive from the password the master-key-decryption-key 
        # (and the password-derived hmac), decrypt the master-key (and master-hmac)
        aes_key, hmac_key, salt, iterations = PassLocker.make_keys(master_password, salt=salt, iterations=iterations)
        hmac = PassLocker.make_hmac(master_password+aes_key, hmac_key)
              
        if master['hmac'] != hmac:
            raise Exception("Master password is incorrect.")
            
        self.unlocked = True
        ciphertext = b64d(master['ciphertext'])
        iv = b64d(master['iv'])
        
        plaintext = PassLocker.decrypt(ciphertext, aes_key, iv)
        self.aes_key = plaintext[0:16]
        self.hmac_key = plaintext[16:32]
            
    def _initialize_master_password(self, checkfile, master_password):
        if len(master_password) < 20:
            print("Your password is less than 20 characters.    To proceed with this week password, please type: weak password")
            ans = input("> ")
            if ans.strip().lower() != "weak password":
                sys.exit(0)
        
        if self.check_pwnedpasswords(master_password):
            print("This password is listed in pwnedpasswords.com.  Please try a different password.")
            raise Exception("This password is listed in pwnedpasswords.com.  Please try a different password.")
        
        verify = self.password_cb("Verify password: ")
        if verify != master_password:
            print("Passwords do not match. Bailing out.")
            sys.exit(0)
                
        # Take the master password, derive the master-key-encryption-key from it
        # Then encrypt the master key with the password-derived key
        # Do the same with the hmac
        
        aes_key, hmac_key, salt, iterations = PassLocker.make_keys(master_password, iterations=self.iterations)
        hmac = PassLocker.make_hmac(master_password+aes_key, hmac_key)
        self.aes_key = secrets.token_bytes(16)
        self.hmac_key = secrets.token_bytes(16)
        ciphertext, iv = PassLocker.encrypt(self.aes_key+self.hmac_key, aes_key)
        master = {
            "algorithm" : "aes-256-cbc",
            'salt' : b64e(salt),
            'iterations' : iterations,
            'hmac' : hmac, # this comes out as a hex string
            'ciphertext' : b64e(ciphertext),
            'iv' : b64e(iv)
        }
        with open(checkfile, 'w') as fh:
            json.dump(master, fh)
            os.chmod(checkfile, 0o600)

        self.unlocked = True

    def check_pwnedpasswords(self, master_password: str) -> bool:
        if type(master_password) == str:
            master_password = master_password.encode('UTF-8')
        hash = sha1(master_password).hexdigest().upper()
        prefix = hash[0:5]
        suffix = hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        with requests.Session() as session:
            req = session.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            body = req.content.decode('UTF-8')
            for line in body.split('\n'):
                check = line.split(':',1)[0]
                if check == suffix:
                    return True
        return False

    def _to_db(self, account, username):
        if type(account) == str:
            account = account.encode('UTF-8')
        if type(username) == str:
            username = username.encode('UTF-8')
        key = account+b'|'+username
        return "%s/%s.json" % (self.dbdir, b64e(key))
        
    def _load_account(self, account_name, username):
        account_file = self._to_db(account_name, username)
        if not os.path.exists(account_file):
            raise Exception("Cannot find entry for %s" % account_name)
    
        with open(account_file, "r") as fh:
            acc = json.load(fh)
        
        return acc
        
    def _write_account(self, account, **kwargs):
        account_name = account['account']
        account_file = self._to_db(account_name, account['username'])
        if kwargs.get('overwrite', True) == False and os.path.exists(account_file):
            raise Exception("Entry for %s (%s) already exists" % (account_name, account['username']))
    
        with open(account_file, "w") as fh:
            json.dump(account, fh)
            os.chmod(account_file, 0o600)
        
    def _unlink_account(self, account_name, username):
        account_file = self._to_db(account_name, username)
        if not os.path.exists(account_file):
            raise Exception("Cannot find entry for %s" % account_name)
        os.unlink(account_file)
            
    # From https://bitbucket.org/brendanlong/python-encryption/src/1737e959fa307d84a5dcf96c4139b1d91a08b2e9/encryption.py?at=master&fileviewer=file-view-default
    @staticmethod
    def make_keys(password, salt=None, iterations=100000):
        """Generates two 128-bit keys from the given password using
             PBKDF2-SHA256.
             We use PBKDF2-SHA256 because we want the native output of PBKDF2 to be
             256 bits. If we stayed at the default of PBKDF2-SHA1, then the entire
             algorithm would run twice, which is slow for normal users, but doesn't
             slow things down for attackers.
             password - The password.
             salt - The salt to use. If not given, a new 8-byte salt will be generated.
             iterations - The number of iterations of PBKDF2 (default=100000).

             returns (k1, k2, salt, interations)
        """
        if salt is None:
                # Generate a random 16-byte salt
                salt = secrets.token_bytes(16)

        # Generate a 32-byte (256-bit) key from the password
        prf = lambda p,s: HMAC.new(p, s, SHA256).digest()
        key = PBKDF2(password, salt, 32, iterations, prf)

        # Split the key into two 16-byte (128-bit) keys
        return key[:16], key[16:], salt, iterations

    @staticmethod
    def make_hmac(message, key):
        """Creates an HMAC from the given message, using the given key. Uses
             HMAC-MD5.
             message - The message to create an HMAC of.
             key - The key to use for the HMAC (at least 16 bytes).

             returns A hex string of the HMAC.
        """
        h = HMAC.new(key)
        h.update(message)
        return h.hexdigest()

    @staticmethod
    def encrypt(message, key):
        """Encrypts a given message with the given key, using AES-CFB.
             message - The message to encrypt (byte string).
             key - The AES key (16 bytes).

             returns (ciphertext, iv). Both values are byte strings.
        """
        # The IV should always be random
        iv = secrets.token_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(message)
        return (ciphertext, iv)

    @staticmethod
    def decrypt(ciphertext, key, iv):
        """Decrypts a given ciphertext with the given key, using AES-CFB.
             message - The ciphertext to decrypt (byte string).
             key - The AES key (16 bytes).
             iv - The original IV used for encryption.

             returns The cleartext (byte string)
        """
        cipher = AES.new(key, AES.MODE_CFB, iv)
        msg = cipher.decrypt(ciphertext)
        return msg

    def change_master_password(self):
        self._unlock()
                
        new_password = self.password_cb()
        if len(new_password) < 20:
            print("Your password is less than 20 characters.    To proceed with this week password, please type: weak password")
            ans = input("> ")
            if ans.strip().lower() != "weak password":
                sys.exit(0)
                
        if type(new_password) == str:
            new_password = new_password.encode('UTF-8')
            
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
        
    def list_accounts(self, sep=' '):
        #s1 = time.time()
        # listdir is 3 times faster than glob (0.4 ms vs. 1.2 ms for 461 files)
        # timing still heavily dependent on os file caching
        files = os.listdir(self.dbdir)
        files = [ x for x in files if x.endswith(".json") ]
        files = sorted(files, key=lambda x: os.stat(self.dbdir+'/'+x).st_mtime)
        #s2 = time.time()
        b64strs = [ x.split('/')[-1][0:-5] for x in files ]
        #s3 = time.time()
        b64decoded = [ b64d(x) for x in b64strs ]
        #s4 = time.time()
        accounts = [ x.decode('UTF-8').replace('|', sep, 1).encode('UTF-8') for x in b64decoded ]
        #s5 = time.time()
        #print("list files: %0.2f, b64str: %0.2f, b64decode: %0.2f, format: %0.2f" % ((s2 - s1)*1000, (s3 - s2)*1000, (s4 - s3)*1000, (s5 - s4)*1000))
        
        return accounts
        
    def add_account(self, account_name, username, **kwargs):
        acc = {
            "account" : account_name,
            "username" : username,
            "created_on" : time.strftime("%Y-%m-%d"),
            "passwords" : [],
            "password.active" : 0,
            "type" : kwargs.get('type', 'password')
        }
        if kwargs.get('type', 'password') == 'totp':
            acc['epoch_start'] = kwargs.get('epoch_start', 0)
            acc['time_interval'] = kwargs.get('time_interval', 30)
            acc['num_digits'] = kwargs.get('num_digits', 6)
            acc['hash_algorithm'] = kwargs.get('hash_algorithm', 'sha1')
            
        self._write_account(acc, overwrite=False)
        return acc
        
    def del_account(self, account_name, username):
        filename = self._to_db(account_name, username)
        if os.path.exists(filename):
            os.unlink(filename)
            return True
        else:
            return False
    
    def add_password(self, account_name, username, password, encoding='UTF-8'):
        self._unlock()
        acc = self._load_account(account_name, username)
        
        if type(password) == str:
            password = password.encode(encoding)
        elif type(password) == bytes:
            encoding = 'bytes'
        else:
            raise Exception("I don't know how to encrypt a password of type %s" % type(password))
    
        ciphertext, iv = PassLocker.encrypt(password, self.aes_key)
        hmac = PassLocker.make_hmac(ciphertext, self.hmac_key)
    
        pw_entry = {
            "added_on" : time.strftime("%Y-%m-%d"),
            "algorithm" : "aes-256-cbc",
            "ciphertext" : b64e(ciphertext),
            "iv" : b64e(iv),
            "hmac" : hmac,
            "encoding" : encoding
        }
             
        if acc.get('passwords') == None:
            acc['passwords'] = []
        
        acc['passwords'].append(pw_entry)
        acc['password.active'] = len(acc['passwords'])
    
        self._write_account(acc)

    def get_active_password(self, account_name, username, **kwargs):
        self._unlock()
        acc = self._load_account(account_name, username)

        pa = acc.get('password.active')
        if pa == 0:
            raise Exception("There is no active password for this account")
            
        if pa > len(acc['passwords']):
            raise Exception("All passwords on this account have been used. No valid passwords remain.")
        
        password = acc['passwords'][pa - 1]
        ciphertext = b64d(password['ciphertext'])
        iv = b64d(password["iv"])

        hmac = PassLocker.make_hmac(ciphertext, self.hmac_key)
        if hmac != password['hmac']:
            raise Exception("HMAC verification of encrypted password failed.")
    
        output_data = PassLocker.decrypt(ciphertext, self.aes_key, iv)
        if password['encoding'] != 'bytes':
            output_data = output_data.decode(password['encoding'])
        if acc['type'] == 'totp':
            output_data = b32d(output_data)
            
        skip = acc.get('password.skip', 0)
        if skip != 0:
            self.set_active_password(account_name, username, pa + skip)
            
        if acc['type'] == 'totp':
            now = kwargs.get('now', time.time())
            tc = int((now - acc["epoch_start"])/acc["time_interval"])
            tc = tc.to_bytes(8, 'big')
            ha = acc['hash_algorithm']
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
            hmac = HMAC.new(output_data, tc, algo)
            output = hmac.digest()
            offset = output[len(output) - 1] & 0xf;
            binary = ((output[offset] & 0x7f) << 24) | ((output[offset + 1] & 0xff) << 16) | ((output[offset + 2] & 0xff) << 8) | (output[offset + 3] & 0xff)
            
            output_data = str(binary)[-acc['num_digits']:].encode('UTF-8')
            
        if kwargs.get('decode') and type(output_data) != str:
            output_data = output_data.decode(kwargs['decode'])
        elif type(output_data) != str:
            output_data = output_data.decode('UTF-8')
        
        return output_data
        
    def set_active_password(self, account_name, username, active_password, **kwargs):
        acc = self._load_account(account_name, username)
        acc['password.active'] = active_password
        if kwargs.get('skip'):
            acc['password.skip'] = kwargs.get('skip')
        self._write_account(acc)
        
    def add_otp_account(self, account_name, username, passwords):
        self._unlock()
        self.add_account(account_name, username, type='otp')
        for pw in passwords:
            self.add_password(account_name, username, pw)
        self.set_active_password(account_name, username, 1, skip=1)
        
    def add_totp_account(self, account_name, username, secret, **kwargs):
        kwargs['type'] = 'totp'
        self._unlock()
        self.add_account(account_name, username, **kwargs)
        self.add_password(account_name, username, secret)
        
    def add_note(self, account_name, username, note):
        # notes are plain text
        acc = self._load_account(account_name, username)
        if acc.get('notes') == None:
            acc['notes'] = list()
        acc['notes'].append(note)
        self._write_account(acc)
        
    def get_notes(self, account_name, username) -> list[str]:
        acc = self._load_account(account_name, username)
        if acc.get('notes') == None:
            return []
        return acc.get('notes')

    def get_type(self, account_name: bytes, username: bytes) -> str:
        acc = self._load_account(account_name, username)
        return acc["type"]
        
    def change_user(self, account_name, from_user, to_user):
        # users are plain text (for now.    I might change this in the future)
        acc = self._load_account(account_name, from_user)
        if type(to_user) == bytes:
            to_user = to_user.decode('UTF-8')
        acc['username'] = to_user
        self._write_account(acc)
        self._unlink_account(account_name, from_user)
        
    def get_user(self, account_name, username):
        return self._load_account(account_name, username).get('username')
        
    def list_notes(self, account_name, username):
        acc = self._load_account(account_name, username)
        return acc.get('notes', [])
        
    def add_question(self, account_name, username, question, answer, encoding = 'UTF-8'):
        self._unlock()
        acc = self._load_account(account_name, username)
        if type(answer) == str:
            answer = answer.encode(encoding)
        elif type(answer) == bytes:
            encoding = 'bytes'
            
        ciphertext, iv = PassLocker.encrypt(answer, self.aes_key)
        hmac = PassLocker.make_hmac(ciphertext, self.hmac_key)
    
        q_entry = {
            "question" : question,
            "added_on" : time.strftime("%Y-%m-%d"),
            "algorithm" : "aes-256-cbc",
            "ciphertext" : b64e(ciphertext),
            "iv" : b64e(iv),
            "encoding" : encoding,
            "hmac" : hmac
        }
        
        if acc.get('questions') == None:
            acc['questions'] = []
        
        acc['questions'].append(q_entry)
        self._write_account(acc)
        
    def list_questions(self, account_name, username):
        acc = self._load_account(account_name, username)
        if acc.get('questions') == None:
            return []
        return( [ x['question'] for x in acc['questions'] ] )
        
    def get_answer(self, account_name, username, idx):
        acc = self._load_account(account_name, username)
        if acc.get('questions') == None:
            return None
        if idx >= len(acc['questions']):
            return None
        self._unlock()
        
        q_entry = acc['questions'][idx]
        
        ciphertext = b64d(q_entry['ciphertext'])
        iv = b64d(q_entry["iv"])

        hmac = PassLocker.make_hmac(ciphertext, self.hmac_key)
        if hmac != q_entry['hmac']:
            raise Exception("HMAC verification of encrypted password failed.")
    
        output_data = PassLocker.decrypt(ciphertext, self.aes_key, iv)
        if q_entry['encoding'] != 'bytes':
            output_data = output_data.decode(q_entry['encoding'])
        return output_data
        
    def rename_account(self, account_name, username, new_account_name, new_username):
        acc = self._load_account(account_name, username)
        if not acc: return
        acc["account"] = new_account_name
        acc["username"] = new_username
        try:
            self._write_account(acc, overwrite=False)
            self._unlink_account(account_name, username)
        except Exception as e:
            print(e)
        
