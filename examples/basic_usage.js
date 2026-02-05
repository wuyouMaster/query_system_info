const jsQuerySystemInfo = require('../dist/index.node');

const connections = jsQuerySystemInfo.getConnections();
for (const connection of connections) {
    console.log(connection.protocol, connection.local_addr, connection.remote_addr, connection.state, connection.pid, connection.inode);
}