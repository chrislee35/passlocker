#!/usr/bin/env python3
import base64
import json
import sys, os
import time
import glob

try:
    import Crypto
except ImportError:
    print("Error: PyCrypto is not installed. You should be able to install it with `pip`. On Fedora and Ubuntu, the pip package is called `python3-pip`, so you should be able to run:\n  sudo apt-get install python3-pip # if you have Ubuntu\n  sudo yum install python3-pip # if you have Fedora\n  sudo python3-pip install pycrypto", file=sys.stderr)
    sys.exit(1)

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA, MD5
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random

BAD_HMAC = 1
BAD_ARGS = 2

class PassLocker:
  def __init__(self, master_password, **kwargs):
    self.master_password = master_password
    self.dbdir = kwargs.get('dbdir', os.environ['HOME']+"/.passlocker")
    self.iterations = kwargs.get('iterations', 100000)
    if not os.path.exists(self.dbdir):
      os.mkdir(self.dbdir)
    check = SHA256.new(b'this is a poor seed'+master_password.encode('UTF-8'))
    checkfile = "{dbdir}/.check".format(dbdir=self.dbdir)
    if os.path.exists(checkfile):
      fh = open(checkfile, 'rb')
      answer = fh.read()
      fh.close()
      if answer != check.digest():
        raise Exception("Master password is incorrect.")
    else:
      fh = open(checkfile, 'wb')
      fh.write(check.digest())
      fh.close()
    
  def list_accounts(self):
    return [base64.b64decode(x.split('/')[-1][0:-5]) for x in glob.glob('%s/*.json' % self.dbdir)]
    
  def _to_db(self, account):
    if type(account) == str:
      account = account.encode('UTF-8')
    return "%s/%s.json" % (self.dbdir, base64.b64encode(account).decode('UTF-8'))
    
  def _load_account(self, account_name):
    account_file = self._to_db(account_name)
    if not os.path.exists(account_file):
      raise Exception("Cannot find entry for %s" % account_name)
  
    fh = open(account_file, "r")
    acc = json.load(fh)
    fh.close()
    
    return acc
    
  def _write_account(self, account_name, account, **kwargs):
    account_file = self._to_db(account_name)
    if kwargs.get('overwrite', True) == False and os.path.exists(account_file):
      raise Exception("Entry for %s already exists" % account_name)
  
    fh = open(account_file, "w")
    json.dump(account, fh)
    fh.close()
    
    
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
        salt = Random.new().read(16)

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
    iv = Random.new().read(AES.block_size)
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
      
    self._write_account(account_name, acc, overwrite=False)
    return acc
  
  def add_password(self, account_name, password):
    acc = self._load_account(account_name)
  
    aes_key, hmac_key, salt, iterations = PassLocker.make_keys(self.master_password, iterations=self.iterations)
    ciphertext, iv = PassLocker.encrypt(password, aes_key)
    hmac = PassLocker.make_hmac(ciphertext, hmac_key)
  
    pw_entry = {
      "added_on" : time.strftime("%Y-%m-%d"),
      "algorithm" : "aes-256-cbc",
      "ciphertext" : base64.b64encode(ciphertext).decode("utf-8"),
      "iv" : base64.b64encode(iv).decode("utf-8"),
      "salt" : base64.b64encode(salt).decode("utf-8"),
      "iterations" : iterations,
      "hmac" : hmac
    }
       
    if acc.get('passwords') == None:
      acc['passwords'] = []
    
    acc['passwords'].append(pw_entry)
    acc['password.active'] = len(acc['passwords'])
  
    self._write_account(account_name, acc)

  def get_active_password(self, account_name, **kwargs):
    acc = self._load_account(account_name)

    pa = acc.get('password.active')
    if pa == 0:
      raise Exception("There is no active password for this account")
      
    if pa > len(acc['passwords']):
      raise Exception("All passwords on this account have been used. No valid passwords remain.")
    
    password = acc['passwords'][pa - 1]
    ciphertext = base64.b64decode(password['ciphertext'])
    salt = base64.b64decode(password['salt'])
    iv = base64.b64decode(password["iv"])
    iterations = password["iterations"]

    aes_key, hmac_key, _, _ = PassLocker.make_keys(self.master_password, salt, iterations)
    hmac = PassLocker.make_hmac(ciphertext, hmac_key)
    if hmac != password['hmac']:
      raise Exception("HMAC verification of encrypted password failed.")
  
    output_data = PassLocker.decrypt(ciphertext, aes_key, iv)
    skip = acc.get('password.skip', 0)
    if skip != 0:
      self.set_active_password(account_name, pa + skip)
      
    if acc['type'] == 'totp':
      now = kwargs.get('now', time.time())
      tc = int((now - acc["epoch_start"])/acc["time_interval"])
      tc = tc.to_bytes(8, 'big')
      if acc['hash_algorithm'] == 'sha1':
        algo = SHA
      elif acc['hash_algorithm'] == 'md5':
        algo = MD5
      elif acc['hash_algorithm'] == 'sha256':
        algo = SHA256
      else:
        raise Exception('unsupported hash algorithm, contact module author')
      # http://pike.lysator.liu.se/docs/ietf/rfc/62/rfc6238.xml
      hmac = HMAC.new(output_data, tc, algo)
      output = hmac.digest()
      offset = output[len(output) - 1] & 0xf;
      binary = ((output[offset] & 0x7f) << 24) | ((output[offset + 1] & 0xff) << 16) | ((output[offset + 2] & 0xff) << 8) | (output[offset + 3] & 0xff)
      
      output_data = str(binary)[-acc['num_digits']:]
        
    return output_data
    
  def set_active_password(self, account_name, active_password, **kwargs):
    acc = self._load_account(account_name)
    acc['password.active'] = active_password
    if kwargs.get('skip'):
      acc['password.skip'] = kwargs.get('skip')
    self._write_account(account_name, acc)
    
  def add_otp_account(self, account_name, passwords):
    self.add_account(account_name, None, type='otp')
    for pw in passwords:
      self.add_password(account_name, pw)
    self.set_active_password(account_name, 1, skip=1)
    
  def add_totp_account(self, account_name, secret, **kwargs):
    kwargs['type'] = 'totp'
    self.add_account(account_name, None, **kwargs)
    self.add_password(account_name, secret)