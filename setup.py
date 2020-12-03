#!/usr/bin/env python

from distutils.core import setup

with open('requirements.txt') as f:
    requirements = f.read().splitlines()
    
setup(name='passlocker',
      version='0.0.7',
      description='Password Encryption',
      author='Chris Lee',
      author_email='python@chrisleephd.us',
      url='https://github.com/chrislee35/passlocker',
      packages=['passlocker'],
      scripts=['bin/passlocker', 'bin/passlocker_cui', 'bin/passlocker_gui'],
      install_requires=requirements,
      classifiers=[
              "Development Status :: 3 - Alpha",
              "Topic :: Utilities",
              "License :: OSI Approved :: MIT License",
          ],
      
     )
