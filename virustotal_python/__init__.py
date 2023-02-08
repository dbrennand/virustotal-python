"""A Python library to interact with the public VirusTotal v3 and v2 APIs.
"""
from virustotal_python.virustotal import Virustotal
from virustotal_python.virustotal import VirustotalResponse
from virustotal_python.virustotal import VirustotalError

name = "virustotal-python"

__all__ = ["Virustotal", "VirustotalResponse", "VirustotalError"]
__author__ = "dbrennand"
__version__ = "1.0.2"
