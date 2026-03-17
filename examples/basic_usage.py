import py_query_system_info

connections = py_query_system_info.get_connections()
for connection in connections:
    print(connection.protocol, connection.local_addr, connection.remote_addr, connection.state, connection.pid, connection.inode)

state = "ESTABLISHED"
connections = py_query_system_info.get_connection_by_state(state)
for connection in connections:
    print(connection.protocol, connection.local_addr, connection.remote_addr, connection.state, connection.pid, connection.inode)

pid = 1
connection = py_query_system_info.get_connection_by_pid(pid)
print(connection.protocol, connection.local_addr, connection.remote_addr, connection.state, connection.pid, connection.inode)

inode = 1
connection = py_query_system_info.get_connection_by_inode(inode)
print(connection.protocol, connection.local_addr, connection.remote_addr, connection.state, connection.pid, connection.inode)

local_addr = "127.0.0.1:8080"
connection = py_query_system_info.get_connection_by_local_addr(local_addr)
print(connection.protocol, connection.local_addr, connection.remote_addr, connection.state, connection.pid, connection.inode)

remote_addr = "127.0.0.1:8080"
connection = py_query_system_info.get_connection_by_remote_addr(remote_addr)
print(connection.protocol, connection.local_addr, connection.remote_addr, connection.state, connection.pid, connection.inode)