'use strict';
const common = require('../common');
const assert = require('assert');
const https = require('https');
const http = require('http');
const net = require('net');
const tls = require('tls');
const dc = require('diagnostics_channel');

dc.subscribe('net.server', common.mustCall(({ server }) => {
  assert.ok(server instanceof net.Server);
}, common.hasCrypto ? 4 : 2)); // eslint-disable-line node-core/crypto-check

dc.subscribe('http.server', common.mustCall(({ server }) => {
  assert.ok(server instanceof http.Server);
}, 1));

net.createServer();

http.createServer();

if (common.hasCrypto) { // eslint-disable-line node-core/crypto-check
  dc.subscribe('tls.server', common.mustCall(({ server }) => {
    assert.ok(server instanceof tls.Server);
  }, 2));

  dc.subscribe('https.server', common.mustCall(({ server }) => {
    assert.ok(server instanceof https.Server);
  }, 1));

  tls.createServer();

  https.createServer();
}
