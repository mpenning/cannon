#!/usr/bin/env python
import os

from setuptools import setup, find_packages
import sys
CURRENT_PATH=os.getcwd()+'/cannon'
sys.path.insert(1,CURRENT_PATH)

def read(fname):
    # Dynamically generate setup(long_description)
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='cannon',
      version="0.0.8",
      description='cannon',
      url='http://github.com/mpenning/cannon',
      author='David Michael Pennington',
      author_email='mike@pennington.net',
      license='GPL',
      platforms='any',
      keywords='',
      entry_points = "",
      long_description=read('README.rst'),
      include_package_data=True,
      packages=find_packages(),
      use_2to3=True,
      zip_safe=False,
      install_requires = ["pexpect", "transitions", "textfsm"],
      setup_requires=[],
      classifiers=[
          'Development Status :: 4 - Beta',
          'Environment :: Plugins',
          'Intended Audience :: Developers',
          'Intended Audience :: System Administrators',
          'Intended Audience :: Information Technology',
          'License :: OSI Approved :: GNU General Public License (GPL)',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python',
          'Topic :: Software Development :: Libraries :: Python Modules',
          ],
     )

