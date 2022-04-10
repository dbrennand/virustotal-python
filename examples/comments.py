"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve comments and interact with them using the VirusTotal API.

Documentation:

    * v3 documentation

        https://developers.virustotal.com/reference/comments
        https://developers.virustotal.com/reference/get-comments
        https://developers.virustotal.com/reference/get-comment
        https://developers.virustotal.com/reference/comment-id-patch
        https://developers.virustotal.com/reference/comment-id-delete
        https://developers.virustotal.com/reference/vote-comment

    * v2 documentation

        https://developers.virustotal.com/v2.0/reference/comments-get
        https://developers.virustotal.com/v2.0/reference/comments-put
"""
from virustotal_python import Virustotal
from base64 import urlsafe_b64encode

API_KEY = "<VirusTotal API Key>"
# The ID (either SHA-256, SHA-1 or MD5 hash) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"
DOMAIN = "google.com"
# Get the domain ID
URL_ID = urlsafe_b64encode("https://github.com/home".encode()).decode().strip("=")
# (Google DNS)
IP = "8.8.8.8"
# There are no comments on this graph so an empty list is returned
GRAPH_ID = "g70fae134aefc4e2f90f069aba47d15a92e0073564310443aa0b6ca3384f5240d"
COMMENT_ID = (
    "f-9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115-07457619"
)

# v3 examples
vtotal = Virustotal(API_KEY=API_KEY)
# Get comments for resources
# Get 10 comments for a file
resp = vtotal.request(f"files/{FILE_ID}/comments", params={"limit": 10})
# Get 2 comments for a URL
resp = vtotal.request(f"urls/{URL_ID}/comments", params={"limit": 2})
# Get 2 comments for a domain
resp = vtotal.request(f"domains/{DOMAIN}/comments", params={"limit": 2})
# Get 5 comments for an IP address
resp = vtotal.request(f"ip_addresses/{IP}/comments", params={"limit": 5})
# Get 3 comments for a graph
resp = vtotal.request(f"graphs/{GRAPH_ID}/comments", params={"limit": 3})

comment = {
    "data": {
        "type": "comment",
        "attributes": {"text": "Watchout! This looks dangerous!"},
    }
}

# Submit comments on a resource
# Submit a comment on a file
resp = vtotal.request(f"files/{FILE_ID}/comments", json=comment, method="POST")
# Submit a comment on a URL
resp = vtotal.request(f"urls/{URL_ID}/comments", json=comment, method="POST")
# Submit a comment on a domain
resp = vtotal.request(f"domains/{DOMAIN}/comments", json=comment, method="POST")
# Submit a comment on a IP address
resp = vtotal.request(f"ip_addresses/{IP}/comments", json=comment, method="POST")
# Submit a comment on a graph
resp = vtotal.request(f"graphs/{GRAPH_ID}/comments", json=comment, method="POST")

# Get the  10 latest comments added to VirusTotal
resp = vtotal.request("comments", params={"limit": 10})
# Get the 10 latest comments added to VirusTotal, filtering for Remote Access Trojan (RAT)
resp = vtotal.request("comments", params={"limit": 10, "filter": "rat"})
# Get a comment based on the ID
resp = vtotal.request(f"comments/{COMMENT_ID}")

edited_comment = {
    "data": {
        "type": "comment",
        "attributes": {"text": "#watchout, this looks quite malicious!"},
    }
}
# Edit a comment based on the ID
resp = vtotal.request(f"comments/{COMMENT_ID}", json=edited_comment, method="PATCH")
# Delete a comment based on the ID
resp = vtotal.request(f"comments/{COMMENT_ID}", method="DELETE")
# Submit a vote for a comment
# Vote options can be either positive, negative or abuse
resp = vtotal.request(
    f"comments/{COMMENT_ID}/vote", json={"data": "positive"}, method="POST"
)

# v2 examples
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION=2)
# Get comments for a given file ID
resp = vtotal.request("comments/get", params={"resource": FILE_ID})
# Create a comment for a given file ID
resp = vtotal.request(
    "comments/put",
    params={"resource": FILE_ID, "comment": "Wow, this looks like a #malicious file!"},
    method="POST",
)
