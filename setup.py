from setuptools import setup, find_packages

with open("README.md", "r") as readme:
    long_description = readme.read()

setup(
    name="virustotal-python",
    version="0.0.6",
    author="Dextroz",
    author_email="dextrozmlg@gmail.com",
    description="A light wrapper around the public VirusTotal API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Dextroz/virustotal-python",
    packages=find_packages(),
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
    ],
    keywords="Light VirusTotal Wrapper Public API",
)
