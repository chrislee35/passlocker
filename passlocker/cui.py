from _io import StringIO
from qrcode import QRCode
from typing import Callable, Literal, LiteralString, cast
from passlocker.models.account import Account
from .passlocker import PassLocker
import getpass
import io
import os
import base64
import pyperclip
from binascii import unhexlify
from pprint import pprint
import secrets
from colorama import Fore, Style

def dec(item: str, encoding: str='raw') -> bytes | str:
    if encoding == 'hex':
        return unhexlify(item)
    elif encoding == 'b64':
        return base64.b64decode(item)
    elif encoding == 'raw':
        return item.encode('UTF-8')
    elif encoding == 'bytes':
        return item
    return item

def pl_prompt(message: str, default: str = "", options: list[str] | None = None) -> str:
    while True:
        if options:
            print("Options: [%s]" % ", ".join(options))
        
        a: str = input(f'{message}: [{default}] ')
        if a == "":
            a = default
        
        if options:
            if a in options:
                return a
            if a in [o[0] for o in options]:
                return a
        else:
            return a

def pl_prompt_int(message: str, default: int = 0) -> int:
    while True:
        a: str = input(f'{message}: [{default}] ')
        if a == "":
            return default
        try:
            return int(a)
        except ValueError:
            return default
            
class CUI:
    def __init__(self,
        password_callback: Callable[[str], bytes] | None = None, 
        dbdir: str | None = None
    ) -> None:
        self.dbdir: str = '%s/.passlocker' % os.environ['HOME']
        if dbdir:
            self.dbdir = dbdir
        self.words: list[str] = list[str]()
        if password_callback is None:
            password_callback = self.get_master_password
        self.pl = PassLocker(password_callback, dbdir=self.dbdir)

    def next_word(self) -> str | None:
        if len(self.words) == 0:
            return None
        word: str = self.words.pop(0)
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
        cmd = pl_prompt("Main menu", "exit", ["list", "add", "genpass", "chpass", "clear", "help", "pwned", "version", "exit"])
        if cmd in ["help", 'h']:
            self.help_main()
        elif cmd in ["list", "l"]:
            self.list_accounts()
        elif cmd in ["add", 'a']:
            self.add_account()
        elif cmd in ["genpass", 'g']:
            _ = self.generate_password_menu()
        elif cmd in ["chpass", "c"]:
            self.pl.change_master_password()
        elif cmd in ['exit', 'e']:
            return False
        elif cmd in ["clear"]:
            _ = os.system("clear")
        elif cmd in ["pwned", "p"]:
            self.check_all_passwords()
        elif cmd in ["version", "v"]:
            print(f"Passlocker version {self.pl.PASSLOCKER_VERSION}")
        return True

    def list_accounts(self):
        filt: str = input("search filter: ")
        item: int = 0
        accounts: list[Account] = [acc for acc in self.pl.accounts() if filt in acc.account or filt in acc.username]
        item = 0
        if len(accounts) == 0:
            print("No accounts found")
            return

        for acc in accounts:
            print(f"{item}\t{acc.account}\t{acc.username}")
            item += 1

        idx: int = pl_prompt_int("entry #", 0)
        if idx >= len(accounts):
            return
        acc: Account = accounts[idx]
        self.edit_account(acc)
        
    def edit_account(self, account: Account):
        accname = account.account
        username = account.username

        while True:
            cmd = pl_prompt(f"{accname} {username}",
                default="exit", 
                options=["help","info","get","copy","qrcode","addpw","genpass","test","del","exit","note","rename","clear","pwned"]
            )
            if cmd in ["help", 'h']:
                self.help_list()
            elif cmd in ["info", 'i']:
                pprint(account)
            elif cmd in ["get", 'g']:
                try:
                    pw: bytes = account.get_active_password()
                    print(Fore.RED+pw.decode('utf-8')+Style.RESET_ALL)
                except Exception as e:
                    print(e)
            elif cmd in ["copy", "c"]:
                try:
                    pw: bytes = account.get_active_password()
                    pyperclip.copy(pw.decode('utf-8'))
                except Exception as e:
                    print(e)
            elif cmd in ["qrcode", "q"]:
                try:
                    pw: bytes = account.get_active_password()
                    self.print_qrcode(pw)
                except Exception as e:
                    print(e)
            elif cmd in ["addpw", 'a']:
                new_password: str = getpass.getpass(f'Enter password for account, {accname}: ')
                if new_password == "":
                    return
                account.add_password(new_password)
                account.save()
            elif cmd in ["genpass", "g"]:
                generated_password: str | None = self.generate_password_menu()
                if generated_password:
                    account.add_password(generated_password)
                    account.save()
            elif cmd in ["test", "t"]:
                pw: bytes = account.get_active_password()
                test: str = getpass.getpass("Type in the password to test: ")
                if pw.decode('utf-8') == test:
                    print(Fore.GREEN+"You got it!"+Style.RESET_ALL)
                else:
                    print(Fore.RED+"Nope, that's not it."+Style.RESET_ALL)
            elif cmd in ["del", 'd']:
                confirm = pl_prompt('Delete account (yes|no)', 'no')
                if confirm and confirm.lower() in ['yes', 'y'] :
                    deleted = account.delete()
                    if deleted:
                        print(f"Account, {account.account}, deleted.")
                        return
                    else:
                        print(f"Cound not delete {account.account}.")
            elif cmd in ["note", 'n']:
                note = input("Note: ")
                if note and len(note) > 0:
                    account.add_note(note)
                    account.save()
            elif cmd in ["rename", "r"]:
                new_account_name: str = pl_prompt("New account name", accname)
                if not new_account_name:
                    continue
                new_username: str = pl_prompt("New user name", username)
                if not new_username:
                    continue
                if new_account_name == account.account and new_username == account.username:
                    continue
                account.change_account_name(new_account_name)
                account.change_username(new_username)
                account.save()
                accname = account.account
                username = account.username
            elif cmd in ["pwned", "p"]:
                
                if account.type != "password":
                    print(Fore.GREEN+"Everything's good."+Style.RESET_ALL)
                else:
                    pw: bytes = account.get_active_password()
                    password: str = pw.decode('utf-8')
                    if self.pl.check_pwnedpasswords(password):
                        print(Fore.RED+"PWNED!"+Style.RESET_ALL)
                    else:
                        print(Fore.GREEN+"Everything's good."+Style.RESET_ALL)
            elif cmd in ["clear"]:
                _ = os.system("clear")
            elif cmd in ['exit', 'e']:
                return
            
    def add_account(self):
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
        account_name: str = self.next_word() or pl_prompt("Account name?")
        username: str = self.next_word() or pl_prompt("Username")

        acc: Account = self.pl.add_account(account_name, username, acc_type='password')
        password: str | None = self.next_word()
        if password:
            if password == '-':
                password = getpass.getpass(f'Enter password for account, {account_name} {username}: ')
                if password == "":
                    return
                acc.add_password(password)
            else:
                acc.add_password(password)
            acc.save()
        else:
            self.edit_account(acc)
        
    def add_otp_account(self):    
        accname: str = self.next_word() or pl_prompt("Account name?")
        username: str = self.next_word() or pl_prompt("Username")
        acc: Account = self.pl.add_account(accname, username, acc_type='otp')
        password: str | None = self.next_word()
        if password:
            # there's a decision that is needed here.    If we add a batch of OTP passwords to
            # a list of existing passwords, should I keep the active password where it's at
            # or point it to the first item of the added items.
            # For now, I will leave the active password index where it's at.
            pa: int = acc.active
            if pa == 0:
                pa = 1
            while password:
                acc.add_password(password)
                password = self.next_word()
            acc.set_active_password(pa)
            acc.save()
        else:
            self.edit_account(acc)

    def add_totp_account(self):
        accname = self.next_word() or pl_prompt("Account name?")
        username = self.next_word() or pl_prompt("Username")
        word = self.next_word()
        if word is None:
            epoch_start = pl_prompt_int('Start time (epoch seconds)', 0)
        else:
            epoch_start = int(word)
        word = self.next_word()
        if word is None:
            time_interval = pl_prompt_int('Time interval (seconds)', 30)
        else:
            time_interval = int(word)
        word = self.next_word()
        if word is None:
            num_digits = pl_prompt_int('Number of digits to return', 6)
        else:
            num_digits = int(word)
        word = self.next_word()
        if word is None or word not in ['sha1', 'md5', 'sha256']:
            hash_algorithm = pl_prompt('Which hash algorithm to use', 'sha1', ['sha1', 'md5', 'sha256', 'sha512'])
        else:
            hash_algorithm = word
        hash_algorithm_literal: Literal['sha1', 'sha256', 'sha512', 'md5'] = cast(Literal["sha1", "sha256", "sha512", "md5"], hash_algorithm)
        

        acc: Account = self.pl.add_account(accname, username, acc_type='totp', 
            totp_epoch_start=epoch_start, totp_time_interval=time_interval, totp_num_digits=num_digits,
            totp_hash_algorithm=hash_algorithm_literal)
        acc.save()
            
        self.edit_account(acc)

    def del_account(self):
        accname = self.next_word() or pl_prompt("Account name?")
        username = self.next_word() or pl_prompt("Username")
        confirm = self.next_word()
        if confirm is None:
            confirm = pl_prompt('Delete account (yes|no)', 'no')
        if confirm and confirm.lower() == 'yes':
            acc = self.pl.get_account(accname, username)
            deleted = acc.delete()
            if deleted:
                print("Account, {accname}, deleted.".format(accname=accname))
            else:
                print("Cound not delete {accname}".format(accname=accname))

    def get_master_password(self, prompt: str) -> bytes:
        return getpass.getpass(prompt=prompt).encode('UTF-8')

    def print_qrcode(self, data: str) -> None:
        qr = QRCode()
        qr.add_data(data)
        f: StringIO = io.StringIO()
        qr.print_ascii(out=f, invert=True)
        _ = f.seek(0)
        print(f.read())

    def generate_password_menu(self) -> str | None:
        gentype: str = pl_prompt("Password type", "memorable", ["memorable", "random", "numbers"])
        length: int = pl_prompt_int("Length", 12)
        count: int = pl_prompt_int("How many passwords?", 1)
        while True:
            passwords: list[str] = []
            for idx in range(count):
                if gentype == "memorable":
                    password = self.generate_memorable(length)
                elif gentype == "random":
                    password = self.generate_random(length)
                elif gentype == "numbers":
                    password = self.generate_numbers(length)
                else:
                    raise Exception(f"Unknown password generation algorithm: {gentype}")
                passwords.append(password)
                print(f"{idx}\t{password}")
            option: str = pl_prompt("Select a password to add. [q] to cancel without adding. Any other character regenerates the list.")
            if option == 'q':
                return None
            if option == 'm':
                continue
            if option.isnumeric():
                idx = int(option)
                if idx > len(passwords):
                    print("You selected an invalid index.")
                else:
                    return passwords[idx]

    def generate_memorable(self, length: int) -> str:
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
            
        random_int: int = secrets.randbelow(maxnum)
        random_special: LiteralString = ''.join(secrets.choice(['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '+', '=', '{', '}', '[', ']', ':', ';', '<', '>', '.', ',', '?', '/', '~', '`']) for i in range(special))
        
        secret_sauce: str = '%d%s' % (random_int, random_special)
        password: str = ""
        
        with open('/usr/share/dict/words') as f:
            words: list[str] = [word.strip() for word in f]
            genlen = 0
            while genlen != length:
                password = secret_sauce.join(secrets.choice(words) for i in range(2))
                genlen: int = len(password)
                
        return password
        
    def generate_random(self, length:int) -> str:
        return secrets.token_urlsafe(32)[0:length]
        
    def generate_numbers(self, length:int) -> str:
        return ''.join([str(secrets.choice(range(10))) for _ in range(length)])

    def check_all_passwords(self) -> None:
        idx = 0
        recs: list[Account] = []
        for acc in self.pl.accounts():            
            account_name = acc.account
            user_name = acc.username
            # be very careful here, if you did this to OTP accounts, it would mess up the current index
            # this is meaningless for TOTP accounts, so skip those too
            if acc.type != "password":
                continue
            pw: bytes = acc.get_active_password()
            # check if this "password" is a pin number
            pin_check: str = pw.decode('utf-8')
            if pin_check.isnumeric() and len(pin_check) < 8:
                continue
            if self.pl.check_pwnedpasswords(pw):
                print(f"{idx} {account_name} {user_name} {Fore.RED}PWNED!{Style.RESET_ALL} {pw}")
                recs.append(acc)
                idx += 1

        idx: int = pl_prompt_int("entry #", 0)
        acc: Account = recs[idx]
        self.edit_account(acc)

def main() -> None:
    cui: CUI = CUI()
    while cui.menu():
        pass
