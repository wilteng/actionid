# Description for `idm` Folder

This folder contains the materials needed to execute the toy example for the identity manager as part of the proof-of-concept implementation. The list of materials are as follow:

## `actionid.py`
The Python package implemented for the proposed scheme. Specifically, the identity manager calls the `issue_token` function from this Python package to service the operations registration by a requestor.

## `idm.py`

The toy example on the usage of `actionid.py` to build the identity manager as part of the proposed scheme. The `issue_token` function requires two additional user-implemented functions as arguments. These two functions are named as `check_policies` and `get_server_public_key` in this file.

- `check_policies`: Checks if the server operations requested by the requestor is compliant with the encoded access control policy of the server in `policies.json`. If so, this function returns the encoded policy.
- `get_server_public_key`: This function returns the public key of the server stored in `servers.db`, which is identified by the server's identifier.

## `idm_private_key.pem`

The private key of the identity manager as required by `actionid.py`. WARNING: Use this only for the demonstration purposes of this toy example.

## `idm_public_key.pem`

The public key of the identity manager as required by `actionid.py`. WARNING: Use this only for the demonstration purposes of this toy example.

## `policies.json`

The access control policy of the server encoded in the JavaScript Object Notation. The policy specifies a blacklist of SQL operations that the requestor under the user group `any` is not permitted to request.

## `servers.db`

An SQL database that stores the identifier and the corresponding public key of the server. This database is consulted during the operations registration of the requestor.