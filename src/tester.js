// Local test rig: a tiny SOCKS5 server whose "outbound" is the proxy under test,
// plus a client that dials HTTP requests through it. A node passes only if we get
// real HTTP bytes back through the tunnel — port-open lies don't count.
import net from 'node:net';

const SOCKS5_VER = 0x05;

// ---- minimal SOCKS5 server (no auth, CONNECT only) --------------------------
export function createSocks5Server(handler, { host = '127.0.0.1', port = 0 } = {}) {
  const server = net.createServer((socket) => {
    let stage = 0;
    socket.on('error', () => socket.destroy());
    socket.on('data', function onData(chunk) {
      if (stage === 0) {
        // greeting: VER NMETHODS METHODS
        if (chunk.length < 2 || chunk[0] !== SOCKS5_VER) {
          socket.destroy();
          return;
        }
        socket.write(Buffer.from([0x05, 0x00])); // no auth
        stage = 1;
        return;
      }
      if (stage === 1) {
        // request: VER CMD RSV ATYP ADDR PORT
        if (chunk.length < 7 || chunk[0] !== SOCKS5_VER || chunk[1] !== 0x01) {
          socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          socket.destroy();
          return;
        }
        const atyp = chunk[3];
        let host, port, rest;
        if (atyp === 0x01 && chunk.length >= 10) {
          host = Array.from(chunk.subarray(4, 8)).join('.');
          port = chunk.readUInt16BE(8);
          rest = chunk.subarray(10);
        } else if (atyp === 0x03 && chunk.length >= 5 + 1 + 2) {
          const len = chunk[4];
          if (chunk.length < 5 + len + 2) return; // wait for more
          host = chunk.subarray(5, 5 + len).toString('ascii');
          port = chunk.readUInt16BE(5 + len);
          rest = chunk.subarray(5 + len + 2);
        } else if (atyp === 0x04 && chunk.length >= 22) {
          host = Array.from({ length: 8 }, (_, i) => chunk.subarray(4 + i * 2, 6 + i * 2).toString('hex')).join(':');
          port = chunk.readUInt16BE(20);
          rest = chunk.subarray(22);
        } else {
          socket.destroy();
          return;
        }
        socket.removeListener('data', onData);
        const upstream = handler({ host, port }, socket, (err) => {
          // SOCKS5 general failure
          socket.write(Buffer.from([0x05, err ? 0x01 : 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          if (err) socket.destroy();
        });
        if (upstream) {
          socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          if (rest && rest.length) upstream.write(rest); // payload that arrived with the handshake
          socket.pipe(upstream).pipe(socket);
          socket.on('close', () => upstream.destroy());
          upstream.on('close', () => socket.destroy());
        }
        stage = 2;
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

// ---- SOCKS5 client ----------------------------------------------------------
export function socksConnect(socksHost, socksPort, targetHost, targetPort, { timeoutMs } = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: socksHost, port: socksPort });
    let done = false;
    const finish = (err, sock) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (err) socket.destroy();
      err ? reject(err) : resolve(sock);
    };
    const timer = setTimeout(() => finish(new Error('socks connect timeout')), timeoutMs || 15000);
    socket.on('error', (e) => finish(e));
    socket.on('connect', () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00])); // client greeting
    });
    let stage = 0;
    let buf = Buffer.alloc(0);
    socket.on('data', function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 0x05 || buf[1] !== 0x00) return finish(new Error('socks auth failed'));
        stage = 1;
        buf = buf.subarray(2);
        const hostBuf = Buffer.from(targetHost);
        const head = Buffer.alloc(4 + 1 + hostBuf.length + 2);
        head[0] = 0x05; // VER
        head[1] = 0x01; // CONNECT
        head[2] = 0x00; // RSV
        head[3] = 0x03; // DOMAINNAME
        head[4] = hostBuf.length;
        hostBuf.copy(head, 5);
        head.writeUInt16BE(targetPort, 5 + hostBuf.length);
        socket.write(head);
        return;
      }
      if (stage === 1) {
        if (buf.length < 10) return;
        if (buf[1] !== 0x00) {
          return finish(new Error(`socks reply ${buf[1]}`));
        }
        socket.removeListener('data', onData);
        finish(null, socket);
      }
    });
  });
}

// ---- HTTP-over-SOCKS test request -------------------------------------------
// Sends a real HTTP/1.1 GET through the SOCKS judge; resolves on any HTTP status
// line + a few body bytes. This is what makes "working" mean "traffic actually
// flowed through the proxy core to the target and back".
export async function httpProbeViaSocks(
  socksHost,
  socksPort,
  targetHost,
  targetPort,
  { timeoutMs = 12000, path = '/', tls = false, minBytes = 16, extraHeaders } = {}
) {
  const { connect: tlsConnect } = await import('node:tls');
  const socket = await socksConnect(socksHost, socksPort, targetHost, targetPort, { timeoutMs });
  return await new Promise((resolve, reject) => {
    let wire = socket;
    let done = false;
    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (err) {
        try { wire.destroy(); } catch {}
        reject(err);
      } else {
        resolve(val);
      }
    };
    const timer = setTimeout(() => finish(new Error(tls ? 'tls/http timeout' : 'http timeout')), timeoutMs);

    const sendRequest = () => {
      const req = [
        `GET ${path} HTTP/1.1`,
        `Host: ${targetHost}`,
        'User-Agent: raysieve/1.0 (+https://github.com/USERNAME/raysieve)',
        'Accept: */*',
        'Connection: close',
        ...(extraHeaders || []),
      ].join('\r\n') + '\r\n\r\n';
      wire.write(req);
    };

    if (tls) {
      wire = tlsConnect(
        { socket, servername: targetHost, rejectUnauthorized: false },
        () => sendRequest()
      );
      wire.on('error', (e) => finish(e));
    } else {
      sendRequest();
    }

    let buffer = Buffer.alloc(0);
    let sawStatus = false;
    let statusLine = '';
    wire.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      const s = buffer.toString('latin1');
      if (!sawStatus) {
        const eol = s.indexOf('\r\n');
        if (eol === -1) return;
        if (!/^HTTP\/1\.[01] \d{3}/i.test(s.slice(0, eol))) {
          finish(new Error(`non-http response: ${s.slice(0, eol).slice(0, 80)}`));
          return;
        }
        sawStatus = true;
        statusLine = s.slice(0, eol);
      }
      // Resolve once we have a status line plus at least minBytes of total response.
      if (buffer.length >= minBytes) {
        const headerEnd = s.indexOf('\r\n\r\n');
        const body = headerEnd >= 0 ? s.slice(headerEnd + 4) : '';
        finish(null, { statusLine, bytes: buffer.length, body });
      }
    });
    wire.on('error', (e) => finish(e));
    wire.on('close', () => {
      // Some servers close right after the body; accept what we got if a status line arrived.
      if (!done && sawStatus) {
        const s = buffer.toString('latin1');
        const headerEnd = s.indexOf('\r\n\r\n');
        finish(null, { statusLine, bytes: buffer.length, body: headerEnd >= 0 ? s.slice(headerEnd + 4) : '' });
      } else {
        finish(new Error('closed before http response'));
      }
    });
  });
}
