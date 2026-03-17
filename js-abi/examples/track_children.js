const { startTrackingChildren } = require('../dist/index.node');

const pid = parseInt(process.argv[2]);
if (!pid) {
    console.error('Usage: node track_children.js <pid>');
    process.exit(1);
}

console.log(`Tracking children of PID: ${pid}`);

const tracker = startTrackingChildren(pid, (child) => {
    console.log('\n[New Child Process]');
    console.log(`  PID: ${child.pid}`);
    console.log(`  PPID: ${child.ppid}`);
    console.log(`  Name: ${child.name}`);
    console.log(`  Command: ${child.cmdline.join(' ')}`);
    console.log(`  Exe: ${child.exePath}`);
});

console.log('Tracking started. Press Ctrl+C to stop...\n');

setTimeout(() => {
    tracker.stop();
    console.log('\nTracking stopped.');
    process.exit(0);
}, 60000);
