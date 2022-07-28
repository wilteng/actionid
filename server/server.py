import socket
import sqlite3
import _thread
import actionid

# Network configurations
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8082      
SERVER_ID = '81258728'
DB_NAME = "fruits.db"

# Setting and listening for connections
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, SERVER_PORT))
print("Listening for operations execution...")
server_socket.listen()

def execute_operations(operations: str, requestor_id_str: str) -> str:
    # Parsing operations
    parsed_ops = []
    for operation in operations.split(";"):
        operation = operation.strip() + ";"
        parsed_ops.append(operation)
    parsed_ops = parsed_ops[:-1]

    # Connect to SQL database and execute operations
    print("Requestor " + requestor_id_str + ": Executing operations")
    db_conn = sqlite3.connect(DB_NAME)
    db_cur = db_conn.cursor()
    for operation in parsed_ops:
        db_cur.execute(operation)
        db_results = db_cur.fetchall()
        db_conn.commit()
    db_conn.close()

    # Build results output
    results = ''
    for row in db_results:
        row_result = '|'
        for field in row:
            row_result = row_result + field + '|'
        results = results + '\n' + row_result

    return results

def handle_requestor(requestor_conn: socket.socket) -> None:
    operations, requestor_id_str, session_key = actionid.check_token(requestor_conn, SERVER_ID)
    results = execute_operations(operations, requestor_id_str)
    actionid.send_session_message(requestor_conn, session_key, results)
    
try:
    while True:
        requestor_conn, requestor_addr = server_socket.accept()
        print("Connection from: " + requestor_addr[0] + ":" + str(requestor_addr[1]))
        _thread.start_new_thread(handle_requestor, (requestor_conn,))
except KeyboardInterrupt:
    server_socket.close()
    exit()