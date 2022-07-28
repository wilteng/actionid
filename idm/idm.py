import json
import socket
import actionid
import sqlite3
import _thread

# Network configurations
IDM_IP = "127.0.0.1"
IDM_PORT = 8081
SERVERS_DB = "servers.db"

# Setting and listening for connections
idm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
idm_socket.bind((IDM_IP, IDM_PORT))
print("Listening for operations registration...")
idm_socket.listen()

# User implemented functions
def check_policies(requestor_conn: socket.socket, operations: str, requestor_id_str: str) -> bytes:
    with open("policies.json") as f:         # Extract policies
        policies = json.load(f)
    
    # Analyse operations against blocked operations
    requestor_group = "any"
    blocked_operations = policies[requestor_group]['blocked_operations']
    if not any(to_find in str(operations) for to_find in blocked_operations):
        print("Requestor " + requestor_id_str + ": Requestor operations are policy-compliant")
        policies = str(policies[requestor_group]).encode()
        return policies
    else:
        print("Requestor " + requestor_id_str + ": Requested operations is not policy-compliant")
        requestor_conn.sendall(b"ERROR: " + str(policies[requestor_group]).encode())
        requestor_conn.close()
        exit()

def get_server_public_key(server_db: str, server_id: str) -> bytes:
    # Load server's public key from database
    db_conn = sqlite3.connect(server_db)
    db_cur = db_conn.cursor()
    db_command = "SELECT public_key FROM servers WHERE id = " + str(server_id)[2:-1]    # HARDCODED VALUE: server's ID
    db_cur.execute(db_command)
    db_results = db_cur.fetchall()
    server_public_key = db_results[0][0].encode().decode('unicode_escape').encode()     # Need to parse escape characters
    return server_public_key

try:
    while True:
        requestor_conn, requestor_addr = idm_socket.accept()
        print("Connection from: " + requestor_addr[0] + ":" + str(requestor_addr[1]))
        _thread.start_new_thread(actionid.issue_token, (requestor_conn, check_policies, get_server_public_key, SERVERS_DB))
except KeyboardInterrupt:
    idm_socket.close()
    exit()