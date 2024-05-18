"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve graphs and interact with them using the VirusTotal v3 API.

Documentation:

    * v3 documentation - https://developers.virustotal.com/reference/graphs
"""

from virustotal_python import Virustotal

API_KEY = "<VirusTotal API Key>"

# Example ID of a graph
GRAPH_ID = "g70fae134aefc4e2f90f069aba47d15a92e0073564310443aa0b6ca3384f5240d"

# v3 examples
vtotal = Virustotal(API_KEY=API_KEY)

# Get 3 graphs from the VirusTotal API
resp = vtotal.request("graphs", params={"limit": 3})
# Get 3 graphs from the VirusTotal API filtering by owner, order and attributes
resp = vtotal.request(
    "graphs",
    params={
        "limit": 2,
        "filter": "owner:hugoklugman",
        "order": "views_count",
        "attributes": "graph_data",
    },
)
# Get a graph using the graph's ID
resp = vtotal.request(f"graphs/{GRAPH_ID}")

# To create a graph, head to https://www.virustotal.com/graph/
