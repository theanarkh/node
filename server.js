const cluster = require('cluster');
const os = require('os');
const http = require('http');
const cpus = os.cpus().length;

if (cluster.isPrimary) {
  const map = {};
  for (let i = 0; i < cpus; i++) {
    const worker = cluster.fork();
    map[worker.process.pid] = 0;
    worker.on('message', (pid) => {
        map[pid]++;
    });
  }

  process.on('SIGINT', () => {
    console.log(map);
  });
} else {
  http.createServer((req, res) => {
      process.send(process.pid);
      res.end('hello');
  }).listen({reuseport: true, port: 8000});
}
