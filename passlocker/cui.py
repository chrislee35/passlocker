from passlocker import PassLocker
import getpass
import io
import json
import os
import sys
import base64
import qrcode
import pyperclip
from binascii import unhexlify
from pprint import pprint
import secrets
from colorama import Fore, Style

def dec(item, encoding='raw'):
    if encoding == 'hex':
        return unhexlify(item)
    elif encoding == 'b64':
        return base64.b64decode(item)
    elif encoding == 'raw':
        return item.encode('UTF-8')
    elif encoding == 'bytes':
        return item
    return item

def pl_prompt(message, default="", options=None):
        while True:
            if options:
                print("Options: [%s]" % ", ".join(options))
            
            a = input('%s: [%s] ' % (message, str(default)))
            if a == None or a == "":
                a = default
            try:
                a = type(default)(a)
            except ValueError:
                return default
            
            if options:
                if a in options:
                    return a
                if a in [o[0] for o in options]:
                    return a
            else:
                return a
            
class CUI:
    def __init__(self, password_callback=None):
        self.password = None
        self.dbdir = '%s/.passlocker' % os.environ['HOME']
        self.pl = None
        self.words = list()
        if password_callback is None:
            password_callback = self.get_master_password
        self.pl = PassLocker(password_callback)

    def next_word(self, use_previous_encoding=False):
        if len(self.words) == 0:
            return None
        word = self.words.pop(0)
        if word in ['hex', 'b64', 'raw']:
            previous_encoding = word
            return dec(self.words.pop(0), word)
        elif use_previous_encoding:
            return dec(word, previous_encoding)
        else:
            return word
        
    def help_main(self):
        print("""help    prints out this help message
list    list password entries
add     creates a new password entry
genpass randomly generates passwords
chpass  change the master password
pwned   check all passwords (via hash) against haveibeenpwned.com
exit    exits the tool""")

    def help_list(self):
        print("""help   prints out this help message
info    provides information about a password entry
get     retrieves password for a password entry
addpw   adds or updates the password for a password entry
del     deletes a password entry
note    add a note to the password entry
rename  rename this account
pwned   check current password (via hash) against haveibeenpwned.com
exit    returns to the top menu""")

    def menu(self):
        cmd = pl_prompt("Main menu", "exit", ["list", "add", "genpass", "chpass", "clear", "help", "pwned", "xport", "exit"])
        if cmd in ["help", 'h']:
            self.help_main()
        elif cmd in ["list", "l"]:
            self.list_accounts()
        elif cmd in ["add", 'a']:
            self.add_account()
        elif cmd in ["genpass", 'g']:
            self.generate_password_menu()
        elif cmd in ["chpass", "c"]:
            self.pl.change_master_password()
        elif cmd in ['xport', 'x']:
            self.export_master_key()
        elif cmd in ['exit', 'e']:
            return False
        elif cmd in ["clear"]:
            os.system("clear")
        elif cmd in ["pwned", "p"]:
            self.check_all_passwords()
        return True

    def list_accounts(self):
        filt = input("search filter: ")
        accs = self.pl.list_accounts('\t')
        if filt:
            accs = [ x for x in accs if filt in str(x) ]
        item = 0
        if len(accs) == 0:
            print("No accounts found")
            return
        for acc in accs:
            print(str(item)+"\t"+acc.decode('UTF-8'))
            item += 1
        cmd = pl_prompt("entry #", "0")
        while cmd == 'h':
            self.help_list()
            cmd = pl_prompt("entry #", "0")
        if cmd == 'x':
            return
        if not cmd.isnumeric():
            return
        i = int(cmd)
        if i >= len(accs):
            return
        accname, username = accs[i].split(b'\t', 1)
        self.edit_account(accname, username)
        
    def edit_account(self, accname, username):
        if type(accname) == str:
            accname = accname.encode('UTF-8')
        if type(username) == str:
            username = username.encode('UTF-8')
            
        while True:
            cmd = pl_prompt("%s %s" % (accname.decode('UTF-8'), username.decode('UTF-8')), "exit", 
                            ["help","info","get","copy","addpw","test","del","exit","note","rename","clear","pwned"])
            if cmd in ["help", 'h']:
                self.help_list()
            elif cmd in ["info", 'i']:
                acc = self.pl._load_account(accname, username)
                pprint(acc)
            elif cmd in ["get", 'g']:
                try:
                    pw = self.pl.get_active_password(accname, username)
                    if type(pw) == bytes: pw = pw.decode("UTF-8")                    
                    print(Fore.RED+pw+Style.RESET_ALL)
                except Exception as e:
                    print(e)
            elif cmd in ["copy", "c"]:
                try:
                    pw = self.pl.get_active_password(accname, username)
                    if type(pw) == bytes: pw = pw.decode("UTF-8")
                    pyperclip.copy(pw)
                except Exception as e:
                    print(e)
            elif cmd in ["addpw", 'a']:
                password = getpass.getpass('Enter password for account, {accname}: '.format(accname=accname.decode('UTF-8')))
                if password == None or password == "":
                    return
                self.pl.add_password(accname, username, password)
            elif cmd in ["test", "t"]:
                pw = self.pl.get_active_password(accname, username)
                test = getpass.getpass("Type in the password to test: ")
                if type(pw) == bytes: pw = pw.decode("UTF-8")
                if pw == test:
                    print(Fore.GREEN+"You got it!"+Style.RESET_ALL)
                else:
                    print(Fore.RED+"Nope, that's not it."+Style.RESET_ALL)
            elif cmd in ["del", 'd']:
                confirm = pl_prompt('Delete account (yes|no)', 'no')
                if confirm and confirm.lower() in ['yes', 'y'] :
                    deleted = self.pl.del_account(accname, username)
                    if deleted:
                        print("Account, {accname}, deleted.".format(accname=accname.decode('UTF-8')))
                        return
                    else:
                        print("Cound not delete {accname}".format(accname=accname.decode('UTF-8')))
            elif cmd in ["note", 'n']:
                note = input("Note: ")
                if note and len(note) > 0:
                    self.pl.add_note(accname, username, note)
            elif cmd in ["rename", "r"]:
                new_account_name = pl_prompt("New account name", accname.decode('UTF-8'))
                if not new_account_name: continue
                new_username = pl_prompt("New user name", username.decode('UTF-8'))
                if not new_username: continue
                if new_account_name == accname.decode('UTF-8') and new_username == username.decode('UTF-8'): continue
                self.pl.rename_account(accname, username, new_account_name, new_username)
                accname = new_account_name.encode('UTF-8')
                username = new_username.encode('UTF-8')
            elif cmd in ["pwned", "p"]:
                rec = self.pl._load_account(accname, username)
                if rec["type"] != "password":
                    print(Fore.GREEN+"Everything's good."+Style.RESET_ALL)
                else:
                    pw = self.pl.get_active_password(accname, username)
                    if type(pw) == bytes: pw = pw.decode("UTF-8")
                    if self.pl.check_pwnedpasswords(pw):
                        print(Fore.RED+"PWNED!"+Style.RESET_ALL)
                    else:
                        print(Fore.GREEN+"Everything's good."+Style.RESET_ALL)
            elif cmd in ["clear"]:
                os.system("clear")
            elif cmd in ['exit', 'e']:
                return
            
    def add_account():
        try:
            acctype = pl_prompt("Which account type?", "password", ["password", "otp", "totp"])
            if acctype in ["password", "pw", "p"]:
                self.add_password_account()
            elif acctype == "otp":
                self.add_otp_account()
            elif acctype == "totp":
                self.add_totp_account()
            else:
                return
        except Exception as e:
            #traceback.print_exc(file=sys.stdout)
            print(e)

    def add_password_account(self):
        accname = next_word() or pl_prompt("Account name?")
        username = next_word() or pl_prompt("Username")
        self.pl.add_account(accname, username, type='password')
        password = next_word()
        if password:
            if password == '-':
                encoding = 'raw'
                password = getpass.getpass('Enter password for account, %s %s (%s): ' % (accname, username, encoding))
                if password == None or password == "":
                    sys.exit(0)
                password = dec(password, encoding)
                self.pl.add_password(accname, username, password)
            else:
                self.pl.add_password(accname, username, password)
        else:
            self.edit_account(accname, username)
        
    def add_otp_account(self):    
        accname = next_word() or pl_prompt("Account name?")
        username = next_word() or pl_prompt("Username")
        self.pl.add_account(accname, username, type='otp')
        password = next_word()
        if password:
            acc = self.pl._load_account(accname, username)
            # there's a decision that is needed here.    If we add a batch of OTP passwords to
            # a list of existing passwords, should I keep the active password where it's at
            # or point it to the first item of the added items.
            # For now, I will leave the active password index where it's at.
            pa = acc.get('password.active')
            if pa == 0:
                pa = 1
            while password:
                self.pl.add_password(accname, username, password)
                password = next_word()
            self.pl.set_active_password(accname, username, pa, skip=1)
        else:
            self.edit_account(accname, username)

    def add_totp_account(self):
        accname = next_word() or pl_prompt("Account name?")
        username = next_word() or pl_prompt("Username")
        word = next_word()
        if word == None:
            epoch_start = pl_prompt('Start time (epoch seconds)', 0)
        else:
            epoch_start = int(word)
        word = next_word()
        if word == None:
            time_interval = pl_prompt('Time interval (seconds)', 30)
        else:
            time_interval = int(word)
        word = next_word()
        if word == None:
            num_digits = pl_prompt('Number of digits to return', 6)
        else:
            num_digits = int(word)
        word = next_word()
        if word == None or not word in ['sha1', 'md5', 'sha256']:
            hash_algorithm = pl_prompt('Which hash algorithm to use', 'sha1', ['sha1', 'md5', 'sha256'])
        else:
            hash_algorithm = word
            
        self.pl.add_account(accname, username, type='totp', 
            epoch_start=epoch_start, time_interval=time_interval, num_digits=num_digits,
            hash_algorithm=hash_algorithm)
            
        self.edit_account(accname, username)

    def del_account(self):
        accname = next_word() or pl_prompt("Account name?")
        username = next_word() or pl_prompt("Username")
        confirm = next_word()
        if confirm == None:
            confirm = pl_prompt('Delete account (yes|no)', 'no')
        if confirm and confirm.lower() == 'yes':
            deleted = self.pl.del_account(accname, username)
            if deleted:
                print("Account, {accname}, deleted.".format(accname=accname))
            else:
                print("Cound not delete {accname}".format(accname=accname))

    def get_master_password(self, prompt):
        return getpass.getpass(prompt=prompt).encode('UTF-8')

    def export_master_key(self):
        pl._unlock()
        export_password = self.get_master_password("Export password: ")
        master = self.pl._create_master_key_record(export_password)
        json_str = json.dumps(master, separators=(',', ':'))
        qr = qrcode.QRCode()
        qr.add_data(json_str)
        f = io.StringIO()
        qr.print_ascii(out=f, invert=True)
        f.seek(0)
        print(f.read())

    def generate_password_menu(self):
        gentype = pl_prompt("Password type", "memorable", ["memorable", "random", "numbers"])
        length = pl_prompt("Length", 12)
        count = pl_prompt("How many passwords?", 1)
        for i in range(count):
            if gentype == "memorable":
                print(self.generate_memorable(length))
            elif gentype == "random":
                print(self.generate_random(length))
            elif gentype == "numbers":
                print(self.generate_numbers(length))

    def generate_memorable(self, length):
        if length <= 8:
            maxnum = 100
            special = 0
        elif length <= 16:
            maxnum = 1000
            special = 1
        elif length <= 24:
            maxnum = 10000
            special = 2
        else:
            maxnum = 100000
            special = 3
            
        random_int = secrets.randbelow(maxnum)
        random_special = ''.join(secrets.choice(['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', ':', ';', '<', '>', '.', ',', '?', '/', '~', '`']) for i in range(special))
        
        secret_sauce = '%d%s' % (random_int, random_special)
        
        with open('/usr/share/dict/words') as f:
            words = [word.strip() for word in f]
            genlen = 0
            while genlen != length:
                password = secret_sauce.join(secrets.choice(words) for i in range(2))
                genlen = len(password)
                
        return password
        
    def generate_random(self, length):
        return secrets.token_urlsafe(32)[0:length]
        
    def generate_numbers(self, length):
        return ''.join([str(secrets.choice(range(10))) for i in range(length)])

    def check_all_passwords(self):
        accs = self.pl.list_accounts('\t')
        recs = []
        idx = 0
        for acc in accs:
            accname, username = acc.split(b'\t', 1)
            try:
                rec = self.pl._load_account(accname, username)
                account_name = accname.decode("UTF-8")
                user_name = username.decode("UTF-8")
                if rec["type"] != "password": continue
                pw = self.pl.get_active_password(accname, username)
                if type(pw) == bytes: pw = pw.decode("UTF-8")
                if pw.isnumeric() and len(pw) < 8: continue
                if self.pl.check_pwnedpasswords(pw):
                    print(f"{idx} {account_name} {user_name} {Fore.RED}PWNED!{Style.RESET_ALL} {pw}")
                    recs.append(acc)
                    idx += 1
            except:
                pass

        cmd = pl_prompt("entry #", 0)
        i = int(cmd)
        accname, username = recs[i].split(b'\t', 1)
        self.edit_account(accname, username)

    @staticmethod
    def main():    
        cui = CUI()
        while cui.menu():
            pass

if __name__ == "__main__":
    CUI.main()