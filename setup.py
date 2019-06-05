import setuptools

import os
from os import listdir
from os.path import isfile, join

mypath = os.path.dirname(os.path.abspath(__file__))
print([f for f in listdir(mypath) if isfile(join(mypath, f))])


with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="aiopaypal",
    version="0.1.4",
    author="Omar Ryhan",
    author_email="omarryhan@gmail.com",
    license="GNU",
    description="Async Paypal client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=["aiohttp", "aiofiles", "pyopenssl"],
    tests_require=["aiohttp", "aiofiles", "pyopenssl", "pytest", "pytest-asyncio"],
    url="https://github.com/omarryhan/aiopaypal",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Operating System :: OS Independent",
    ],
)
