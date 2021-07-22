'use strict';
const assert = require('internal/assert');
const net = require('net');
const { constants: TCPConstants } = internalBinding('tcp_wrap');
module.exports = ReusePort;

function ReusePort(key, address, {port, addressType, fd, flags}) {
  this.key = key;
  this.workers = [];
  this.handles = [];
  this.list = [address, port, addressType, fd, flags];
}

ReusePort.prototype.add = function(worker, send) {
  assert(!this.workers.includes(worker));
  const rval = net._createServerHandle(...this.list);
  let errno;
  let handle;
  if (typeof rval === 'number')
    errno = rval;
  else
    handle = rval;
  this.workers.push(worker);
  this.handles.push(handle);
  send(errno, null, handle);
};

ReusePort.prototype.remove = function(worker) {
  const index = this.workers.indexOf(worker);

  if (index === -1)
    return false; // The worker wasn't sharing this handle.

  this.workers.splice(index, 1);
  this.handles[index].close();
  this.handles.splice(index, 1);
  return true;
};
