#!/usr/bin/env python

from distutils.core import setup

setup(name='passlocker',
    version='0.0.9',
    description='Password Encryption',
    author='Chris Lee',
    author_email='python@chrisleephd.us',
    url='https://github.com/chrislee35/passlocker',
    packages=['passlocker'],
    scripts=['bin/passlocker', 'bin/passlocker_cui', 'bin/passlocker_rename'],
    install_requires=[
        "pycryptodome",
        "pyperclip",
        "pwinput"
    ],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :'': Utilities",
        "License :: OSI Approved :: MIT License",
    ]
)
