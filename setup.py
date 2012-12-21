#!/usr/bin/env python
from setuptools import setup

from slbackup import __version__

setup(name='slbackup',
      version=__version__,
      description='Backup utility for SWIFT object storage',
      author='Kevin Landreth',
      author_email='klandreth@softlayer.com',
      url="https://github.com/softlayer/softlayer-object-storage-backup",
      license='MIT',
      include_package_data=True,
      zip_safe=False,
      install_requires=['softlayer-object-storage>=0.4.6'],
      scripts=['slbackup.py'],
      classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Console',
        'Programming Language :: Python',
        'Operating System :: POSIX :: Linux',
        'Environment :: Console',
        'License :: OSI Approved :: MIT License',
        ],
      )
