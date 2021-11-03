from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf8") as readme:
    long_description = readme.read()

setup(
    name="virustotal-python",
    version="0.2.0",
    author="dbrennand",
    description="A Python library to interact with the public VirusTotal v2 and v3 APIs.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/dbrennand/virustotal-python",
    packages=find_packages(),
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
    ],
    keywords="VirusTotal Wrapper Public API Library v2 v3",
)
