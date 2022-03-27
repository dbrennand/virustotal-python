"""A Python library to interact with the public VirusTotal v2 and v3 APIs.
"""
from virustotal_python.virustotal import Virustotal
from virustotal_python.virustotal import VirustotalError

name = "virustotal-python"

__all__ = ["Virustotal", "VirustotalError"]
__author__ = "dbrennand"
__version__ = "0.3.0"
