#!/usr/bin/env python

import os, sys, glob, subprocess, textwrap

try:
    import setuptools
    assert int(setuptools.__version__.split(".", 1)[0]) >= 19
except (ImportError, AssertionError):
    msg = 'Error: Aegea failed to install because your version of setuptools is too old ({}; 19 is required). Run "make install_venv" to install aegea in its own virtualenv, or upgrade your pip and setuptools to their latest versions.' # noqa
    exit(textwrap.fill(msg.format(setuptools.__version__)))

try:
    # Git version extraction logic designed to be compatible with both semver and PEP 440
    version = subprocess.check_output(["git", "describe", "--tags", "--match", "v*.*.*"]).decode()
    version = version.strip("v\n").replace("-", "+", 1).replace("-", ".")
except Exception:
    version = "0.0.0"

setuptools.setup(
    name="aegea",
    version=version,
    url="https://github.com/kislyuk/aegea",
    license=open("LICENSE.md").readline().strip(),
    author="Andrey Kislyuk",
    author_email="kislyuk@gmail.com",
    description="Amazon Web Services Operator Interface",
    long_description=open("README.rst").read(),
    install_requires=[
        "boto3 >= 1.9.140, < 2",
        "argcomplete >= 1.9.5, < 2",
        "paramiko >= 2.4.2, < 3",
        "requests >= 2.18.4, < 3",
        "tweak >= 1.0.2, < 2",
        "keymaker >= 1.0.8, < 2",
        "pyyaml >= 3.12, < 6",
        "python-dateutil >= 2.6.1, < 3",
        "babel >= 2.4.0, < 3",
        "ipwhois >= 1.1.0, < 2",
        "uritemplate >= 3.0.0, < 4",
        "awscli >= 1.16.150, < 2"
    ],
    extras_require={
        ':python_version == "2.7"': [
            "enum34 >= 1.1.6, < 2",
            "ipaddress >= 1.0.19, < 2",
            "subprocess32 >= 3.2.7, < 4"
        ],
        'awslambda': [
            "chalice >= 1.1.1, < 2"
        ]
    },
    tests_require=[
        "coverage",
        "flake8"
    ],
    packages=setuptools.find_packages(exclude=["test"]),
    scripts=glob.glob("scripts/*"),
    platforms=["MacOS X", "Posix"],
    test_suite="test",
    include_package_data=True
)
