"""
The examples in this file are for virustotal-python version >=0.1.0

Retrieve comments and interact with them using the VirusTotal API.

Documentation:

    * v2 documentation - https://developers.virustotal.com/reference#comments-get

        * https://developers.virustotal.com/reference#comments-put

    * v3 documentation - https://developers.virustotal.com/v3.0/reference#comments-1
"""
from virustotal_python import Virustotal
from base64 import urlsafe_b64encode
from pprint import pprint

API_KEY = "Insert API key here."

# The ID (either SHA-256, SHA-1 or MD5) identifying the file
FILE_ID = "9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115"

# URL/domain identifier
URL = "google.com"

# Obtain the URL ID
URL_ID = urlsafe_b64encode(URL.encode()).decode().strip("=")

# Example IP address (Google DNS)
IP = "8.8.8.8"

# Example ID of a graph
## NOTE: There are no comments on this graph so an empty list is returned
GRAPH_ID = "g70fae134aefc4e2f90f069aba47d15a92e0073564310443aa0b6ca3384f5240d"

# Example comment ID
COMMENT_ID = "f-9f101483662fc071b7c10f81c64bb34491ca4a877191d464ff46fd94c7247115-07457619"

# v3 examples
vtotal = Virustotal(API_KEY=API_KEY, API_VERSION="v3")

## Retriving comments for resources
### Retrieve 10 comments for a file
resp = vtotal.request(f"files/{FILE_ID}/comments", params={"limit": 10})
### Retrieve 2 comments for a URL
resp = vtotal.request(f"urls/{URL_ID}/comments", params={"limit": 2})
### Retrieve 2 comments for a domain
resp = vtotal.request(f"domains/{URL}/comments", params={"limit": 2})
### Retrieve 5 comments for an IP address
resp = vtotal.request(f"ip_addresses/{IP}/comments", params={"limit": 5})
### Retrieve 3 comments for a graph
resp = vtotal.request(f"graphs/{GRAPH_ID}/comments", params={"limit": 3})

## Submit a comment on a file, URL, domain, IP address or graph.
## Prepare comment JSON
comment = {
    "data": {
        "type": "comment",
        "attributes": {
            "text": "Watchout! This looks dangerous!"
        }
    }
}

## Submit comments on a resource
### Submit a comment on a file
resp = vtotal.request(f"files/{FILE_ID}/comments", json=comment, method="POST")
### Submit a comment on a URL
resp = vtotal.request(f"urls/{URL_ID}/comments", json=comment, method="POST")
### Submit a comment on a domain
resp = vtotal.request(f"domains/{URL}/comments", json=comment, method="POST")
### Submit a comment on a IP address
resp = vtotal.request(f"ip_addresses/{IP}/comments", json=comment, method="POST")
### Submit a comment on a graph
resp = vtotal.request(f"graphs/{GRAPH_ID}/comments", json=comment, method="POST")

## Retrieve the latest comments added to VirusTotal
### Retrieve the 10 latest comments added to VirusTotal with no filter
resp = vtotal.request("comments", params={"limit": 10})
### Retrieve the 10 latest comments added to VirusTotal, filtering for Remote Access Trojan (RAT)
#### When testing, for some reason there are comments that are returned which don't contain the tag 🤔
resp = vtotal.request("comments", params={"limit": 10, "filter": "rat"})
### Retrieve a specific comment based on the ID
resp = vtotal.request(f"comments/{COMMENT_ID}")
### Edit a specific comment based on the ID
#### Prepare comment JSON
# Old comment was '#watchout, this looks very malicious!'
edited_comment = {
    "data": {
        "type": "comment",
        "attributes": {
            "text": "#watchout, this looks quite malicious!"
        }
    }
}
resp = vtotal.request(f"comments/{COMMENT_ID}", json=edited_comment, method="PATCH")
### Delete a comment based on the ID
resp = vtotal.request(f"comments/{COMMENT_ID}", method="DELETE")
### Submit a vote for a comment
#### Vote options can be either positive, negative, abuse
### Submit a positive vote on a comment based on the comment ID
# This is what I got working
# The documentation on this endpoint is confusing... If you look you will see :-D
# https://developers.virustotal.com/v3.0/reference#vote-comment
resp = vtotal.request(f"comments/{COMMENT_ID}/vote", json={"data": "positive"}, method="POST")

# v2 examples
vtotal = Virustotal(API_KEY=API_KEY)

# Retrieve comments for a given file ID
resp = vtotal.request("comments/get", params={"resource": FILE_ID})

pprint(resp.json())

# Create a comment for a given file ID
resp = vtotal.request("comments/put", params={"resource": FILE_ID, "comment": "Wow, this looks like a #malicious file!"}, method="POST")
