const jsQuerySystemInfo = require('../dist/index.node');

// const connections = jsQuerySystemInfo.getConnections();
// for (const connection of connections) {
//     console.log(connection.protocol, connection.localAddr, connection.remoteAddr, connection.state, connection.pid, connection.inode);
// }

const systemSummary = new jsQuerySystemInfo.JsSystemSummary(1);
const connections = systemSummary.getConnections();
for (const connection of connections) {
    console.log(connection.protocol, connection.localAddr, connection.remoteAddr, connection.state, connection.pid, connection.inode);
}
const processes = systemSummary.getProcesses();
for (const process of processes) {
    console.log(process.pid, process.name, process.command, process.status, process.memoryUsage);
}
const processCount = systemSummary.getProcessCount();
console.log(processCount);
const cpuUsage = systemSummary.getCpuUsage();
console.log(cpuUsage);