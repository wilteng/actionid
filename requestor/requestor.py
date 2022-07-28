import actionid

# Network configurations
IDM_IP = "127.0.0.1"
IDM_PORT = 8081
SERVER_IP = "127.0.0.1"
SERVER_PORT = 8082
server_id = '81258728'

# Execute data pull operation
operations = 'SELECT * FROM fruits;'
token = actionid.register_operations(IDM_IP, IDM_PORT, server_id, operations)
results = actionid.access_service(SERVER_IP, SERVER_PORT, operations, token)
print('\n"fruits" table:' + results)

# Execute data push and pull operation
operations = 'INSERT INTO fruits ("fruit", "colour") VALUES ("grapes", "purple"); SELECT * FROM fruits;'
token = actionid.register_operations(IDM_IP, IDM_PORT, server_id, operations)
results = actionid.access_service(SERVER_IP, SERVER_PORT, operations, token)
print('\n"fruits" table:' + results)