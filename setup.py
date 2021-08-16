#!/usr/bin/env python3
import sys

from setuptools import setup

VERSION = "1.0.4"


# Main
setup(
    name="tekover",
    version=VERSION,
    description="A subdomain takeover scanner using Python3 asyncio",
    url="https://github.com/devl00p/tekover",
    author="Nicolas Surribas",
    author_email="nicolas.surribas@gmail.com",
    license="GPLv2",
    platforms=["Any"],
    packages=["tekover"],
    package_data={"tekover": ["data/fingerprints.json", "data/resolvers.txt", "data/subdomain-wordlist.txt"]},
    include_package_data=True,
    zip_safe=False,
    scripts=[
        "bin/tekover",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Operating System :: Unix",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
    install_requires=[
        "httpx==0.18.2",
        "dnspython==2.1.0",
        "tld==0.12.6",
        "rich==10.6.0"
    ],
    entry_points={
        "console_scripts": [
            "tekover = tekover.tekover:tekover_main_wrapper",
        ]
    }
)
