import unittest, os, glob
from passlocker import PassLocker

class PassLockerTest(unittest.TestCase):
  def setUp(self):
    for acc in glob.glob('db/*.json'):
      os.unlink(acc)
    if os.path.exists('db/.check'):
      os.unlink('db/.check')
    
  def test_regular_password(self):
    pl = PassLocker("mastermastermastermaster", iterations=10, dbdir='db/') # for testing
    pl.add_account("test", "chris")
    pl.add_password("test", "chris", b"password")
    self.assertEqual(b"password", pl.get_active_password("test", "chris"))
    
  def test_otp(self):
    pl = PassLocker("mastermastermastermaster", iterations=10, dbdir='db/') # for testing
    pl.add_otp_account("otp_test", "chris", [b"a",b"b",b"c",b"d",b"e",b"f"])
    self.assertEqual(b"a", pl.get_active_password("otp_test", "chris"))
    self.assertEqual(b"b", pl.get_active_password("otp_test", "chris"))
    self.assertEqual(b"c", pl.get_active_password("otp_test", "chris"))
    self.assertEqual(b"d", pl.get_active_password("otp_test", "chris"))
    self.assertEqual(b"e", pl.get_active_password("otp_test", "chris"))
    self.assertEqual(b"f", pl.get_active_password("otp_test", "chris"))
    with self.assertRaisesRegex(Exception, 'All passwords on this account have been used. No valid passwords remain.'):
      pl.get_active_password("otp_test", "chris")

  def test_totp(self):
    pl = PassLocker("mastermastermastermaster", iterations=10, dbdir='db/') # for testing
    key = "12345678901234567890".encode('UTF-8')
    pl.add_totp_account("totp_test", "chris", key, num_digits=8, time_interval=30)
    answers = ["94287082", "07081804", "14050471", "89005924", "69279037", "65353130"]
    for now in [59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000]:
      result = pl.get_active_password("totp_test", "chris", now=now)
      answer = answers.pop(0)
      self.assertEqual(answer, result)
      
  def test_utf8(self):
    pl = PassLocker("生麦生米生卵生麦生米生卵生麦生米生卵", iterations=10, dbdir='db/') # for testing
    pl2 = PassLocker("生麦生米生卵生麦生米生卵生麦生米生卵", iterations=10, dbdir='db/') # for testing
    pl2.add_account("テスト","クリス")
    pl2.add_password("テスト","クリス","マジで？ホンマに？何でやねん？")
    self.assertEqual("マジで？ホンマに？何でやねん？", pl2.get_active_password("テスト","クリス", decode='UTF-8'))
    
  def test_username(self):
    pl = PassLocker("mastermastermastermaster", iterations=10, dbdir='db/') # for testing
    pl.add_account("test", "chris")
    self.assertEqual("chris", pl.get_user('test', "chris"))
    pl.change_user("test", "chris", "bill")
    self.assertEqual("bill", pl.get_user('test', "bill"))
    
  def test_questions(self):
    pl = PassLocker("mastermastermastermaster", iterations=10, dbdir='db/') # for testing
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
    pl = PassLocker("mastermastermastermaster", iterations=10, dbdir='db/') # for testing
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
