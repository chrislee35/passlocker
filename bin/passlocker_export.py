#!/usr/bin/env python3
from passlocker import PassLocker
import getpass
import os
import subprocess
import requests

def get_master_password(prompt):
    return getpass.getpass(prompt=prompt).encode('UTF-8')

password = None
dbdir = '%s/.passlocker' % os.environ['HOME']
pl = PassLocker(get_master_password)
accs = pl.list_accounts('\t')
hostname = os.environ.get('NEXTCLOUD_HOST')
if hostname is None:
    hostname = input("What hostname is your nextcloud server at? e.g., example.com: ")
prefix = os.environ.get('NEXTCLOUD_PREFIX')
if prefix is None:
    prefix = input("What URL path, if any, is your nextcloud server at? e.g., / or /nextcloud or /nc: ")

baseurl = f"https://{hostname}/{prefix}/index.php/apps/passwords/api/1.0".replace('//', '/')
print(f"The Password API URL is: {baseurl}")

username = os.environ.get('NEXTCLOUD_USER', os.environ.get('USERNAME', os.environ.get('USER')))
if username is None:
    username = input("What is your nextcloud username? ")
else:
    username2 = input(f"What is your nextcloud username? default: {username}: ")
    if username2:
        username = username2

password = getpass.getpass(f"Nextcloud password for {username}: ")
with requests.Session() as sess:
    sess.auth = (username, password)
    r = sess.get(f"{baseurl}/session/request",)
    r = sess.post(f"{baseurl}/session/open")
    
    for acc in accs:
        accname, username = acc.split(b'\t', 1)
        try:
            t = pl.get_type(accname, username)
            # only upload "password" entries, not topt, otp, etc.
            if t != "password": continue
            pw = pl.get_active_password(accname, username)
            rec = {
                "password": pw.decode("UTF-8"),
                "username": username,
                "label": accname
            }
            if accname.startswith("http"):
                rec["url"] = accname
            notes = pl.get_notes(accname, username)
            if notes:
                rec["notes"] = "\n".join(notes)
            r = sess.post(f"{baseurl}/password/create", json=body)
        except:
            pass

    print(r.status_code)
    print(r.content)