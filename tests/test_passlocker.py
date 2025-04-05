import unittest
import os
import glob
from base64 import b32encode
from passlocker import PassLocker

class PassLockerTest(unittest.TestCase):
    def setUp(self):
        for acc in glob.glob('db/*.json'):
            os.unlink(acc)
        if os.path.exists('db/.check'):
            os.unlink('db/.check')
            
    def get_master_pw(self, prompt):
        return "mastermastermastermaster098345729834765938".encode('UTF-8')

    def get_pwned_pw(self, prompt):
        return "passwordpassword123456".encode('UTF-8')

    def test_pwned_password(self):
        with self.assertRaises(Exception):
            pl = PassLocker(self.get_pwned_pw, iterations=10, dbdir='db/') # for testing
            pl.add_account("test", "chris")
            pl.add_password("test", "chris", b"password")
        
    def test_regular_password(self):
        pl = PassLocker(self.get_master_pw, iterations=10, dbdir='db/') # for testing
        pl.add_account("test", "chris")
        pl.add_password("test", "chris", b"password")
        self.assertEqual("password", pl.get_active_password("test", "chris"))
        
    def test_otp(self):
        pl = PassLocker(self.get_master_pw, iterations=10, dbdir='db/') # for testing
        pl.add_otp_account("otp_test", "chris", [b"a",b"b",b"c",b"d",b"e",b"f"])
        self.assertEqual("a", pl.get_active_password("otp_test", "chris"))
        self.assertEqual("b", pl.get_active_password("otp_test", "chris"))
        self.assertEqual("c", pl.get_active_password("otp_test", "chris"))
        self.assertEqual("d", pl.get_active_password("otp_test", "chris"))
        self.assertEqual("e", pl.get_active_password("otp_test", "chris"))
        self.assertEqual("f", pl.get_active_password("otp_test", "chris"))
        with self.assertRaisesRegex(Exception, 'All passwords on this account have been used. No valid passwords remain.'):
            pl.get_active_password("otp_test", "chris")

    def make_test_totp_key(self, length):
        return b32encode("".join([ str((x+1)%10) for x in range(length)]).encode('ASCII')).decode('ASCII')
    
    def test_totp(self):
        pl = PassLocker(self.get_master_pw, iterations=10, dbdir='db/') # for testing
        
        test_vectors = [
            (59,"94287082","sha1"),
            (59,"46119246","sha256"),
            (59,"90693936","sha512"),
            (1111111109,"07081804","sha1"),
            (1111111109,"68084774","sha256"),
            (1111111109,"25091201","sha512"),
            (1111111111,"14050471","sha1"),
            (1111111111,"67062674","sha256"),
            (1111111111,"99943326","sha512"),
            (1234567890,"89005924","sha1"),
            (1234567890,"91819424","sha256"),
            (1234567890,"93441116","sha512"),
            (2000000000,"69279037","sha1"),
            (2000000000,"90698825","sha256"),
            (2000000000,"38618901","sha512"),
            (20000000000,"65353130","sha1"),
            (20000000000,"77737706","sha256"),
            (20000000000,"47863826","sha512")
        ]
        
        sha1_key   = self.make_test_totp_key(20)
        sha256_key = self.make_test_totp_key(32)
        sha512_key = self.make_test_totp_key(64)
        pl.add_totp_account("totp_test_sha1", "chris", sha1_key, num_digits=8, time_interval=30, hash_algorithm='sha1')
        pl.add_totp_account("totp_test_sha256", "chris", sha256_key, num_digits=8, time_interval=30, hash_algorithm='sha256')
        pl.add_totp_account("totp_test_sha512", "chris", sha512_key, num_digits=8, time_interval=30, hash_algorithm='sha512')
        for tv in test_vectors:
            result = pl.get_active_password(f"totp_test_{tv[2]}", "chris", now=tv[0])
            self.assertEqual(tv[1], result)
            
    def test_utf8(self):
        PassLocker(lambda x: "生麦生米生卵生麦生米生卵生麦生米生卵".encode('UTF-8'), iterations=10, dbdir='db/') # for testing
        pl2 = PassLocker(lambda x: "生麦生米生卵生麦生米生卵生麦生米生卵".encode('UTF-8'), iterations=10, dbdir='db/') # for testing
        pl2.add_account("テスト","クリス")
        pl2.add_password("テスト","クリス","マジで？ホンマに？何でやねん？")
        self.assertEqual("マジで？ホンマに？何でやねん？", pl2.get_active_password("テスト","クリス", decode='UTF-8'))
        
    def test_username(self):
        pl = PassLocker(self.get_master_pw, iterations=10, dbdir='db/') # for testing
        pl.add_account("test", "chris")
        self.assertEqual("chris", pl.get_user('test', "chris"))
        pl.change_user("test", "chris", "bill")
        self.assertEqual("bill", pl.get_user('test', "bill"))
        
    def test_questions(self):
        pl = PassLocker(self.get_master_pw, iterations=10, dbdir='db/') # for testing
        pl.add_account("test", "chris")
        pl.add_question("test", "chris", "name of dog", "jack")
        pl.add_question("test", "chris", "name of cat", "pantsalot")
        pl.add_question("test", "chris", "city of first kiss", "mossville")
        answer = ["name of dog", "name of cat", "city of first kiss"]
        self.assertEqual(answer, pl.list_questions("test", "chris"))
        self.assertEqual("jack", pl.get_answer("test", "chris", 0))
        self.assertEqual("pantsalot", pl.get_answer("test", "chris", 1))
        self.assertEqual("mossville", pl.get_answer("test", "chris", 2))
        
    def test_notes(self):
        pl = PassLocker(self.get_master_pw, iterations=10, dbdir='db/') # for testing
        pl.add_account("test", "chris")
        pl.add_note("test", "chris", "this is a note")
        pl.add_note("test", "chris", "this is another note")
        answer = [ "this is a note", "this is another note" ]
        self.assertEqual(answer, pl.get_notes("test", "chris"))
        
    def tearDown(self):
        for acc in glob.glob('db/*.json'):
            os.unlink(acc)
        if os.path.exists('db/.check'):
            os.unlink('db/.check')

if __name__ == '__main__':
    unittest.main()
