import { mkdir, open, readFile } from "node:fs/promises";
import { createServer, Socket } from "node:net";
import { resolve } from "node:path";
import { connect as tlsConnect, TLSSocket } from "node:tls";
import { promisify } from "node:util";
import { fileURLToPath } from "url";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

const tcpServer = createServer();
const port = await new Promise<void>((res) => tcpServer.listen(0, res)).then(
  () => {
    const address = tcpServer.address();
    if (address == null || typeof address !== "object")
      throw new Error("server not listening");
    return address.port;
  }
);

console.log(`server listening at port: ${port}`);

const clientSocket = new Socket();
clientSocket.on("end", () => clientSocket.end());

const [serverClientSocket] = await Promise.all([
  new Promise<Socket>((res, rej) => {
    tcpServer.once("error", rej);
    tcpServer.once("connection", (socket) => {
      res(socket);
      tcpServer.removeListener("error", rej);
    });
  }),
  new Promise<void>((res, rej) => {
    clientSocket.once("error", rej);
    clientSocket.once("connect", () => {
      res();
      clientSocket.removeListener("error", rej);
    });
    clientSocket.connect({ port });
  }),
]);

console.log(`client connected`);

serverClientSocket.on("timeout", () =>
  serverClientSocket.destroy(new Error("serverClientSocket timeout"))
);
serverClientSocket.on("end", () => serverClientSocket.end());
serverClientSocket.on("close", () => tcpServer.close());

const [helloFromServer, helloFromClient] = await Promise.all([
  new Promise<Buffer>((res, rej) => {
    clientSocket.once("error", rej);
    clientSocket.once("data", (data) => {
      res(data);
      clientSocket.removeListener("error", rej);
    });
  }),
  new Promise<Buffer>((res, rej) => {
    serverClientSocket.once("error", rej);
    serverClientSocket.once("data", (data) => {
      res(data);
      serverClientSocket.removeListener("error", rej);
    });
  }),
  promisify(clientSocket.write.bind(clientSocket))("Hello from client"),
  promisify(serverClientSocket.write.bind(serverClientSocket))(
    "Hello from server"
  ),
]);

console.log({
  helloFromClient: helloFromClient.toString(),
  helloFromServer: helloFromServer.toString(),
});

const [ca, serverCert, serverKey, clientCert, clientKey] = await Promise.all([
  readFile(resolve(__dirname, "certs/ca/ca.crt")),
  readFile(resolve(__dirname, "certs/server/server.crt")),
  readFile(resolve(__dirname, "certs/server/server.key")),
  readFile(resolve(__dirname, "certs/client/client.crt")),
  readFile(resolve(__dirname, "certs/client/client.key")),
]);

const [serverTlsKeyLog, clientTlsKeyLog] =
  (await mkdir("tmp").catch(() => {}),
  await Promise.all([
    open(resolve(__dirname, "tmp/server-ssl-keys.log"), "w").then((fh) =>
      fh.createWriteStream()
    ),
    open(resolve(__dirname, "tmp/client-ssl-keys.log"), "w").then((fh) =>
      fh.createWriteStream()
    ),
  ]));

const serverTlsSocket = new TLSSocket(serverClientSocket, {
  enableTrace: true,
  isServer: true,
  cert: serverCert,
  key: serverKey,
  ca,
  requestCert: true,
});

console.log(`server tls socket created`);

serverTlsSocket.on("keylog", (line) => serverTlsKeyLog.write(line));

const serverTlsSocketSession = (async () => {
  while (true) {
    const { errored, closed } = serverTlsSocket;
    if (errored) throw errored;
    if (closed) throw new Error("serverTlsSocket closed");
    const session = serverTlsSocket.getSession();
    if (session) return session;
    await new Promise<void>((res) => setImmediate(res));
  }
})();

// server hello sent, request client certificate
const serverTlsSocketGetFinished = (async () => {
  while (true) {
    const { errored, closed } = serverTlsSocket;
    if (errored) throw errored;
    if (closed) throw new Error("serverTlsSocket closed");
    const finished = serverTlsSocket.getFinished();
    if (finished) return finished;
    await new Promise<void>((res) => setImmediate(res));
  }
})();

// server-side handshake done, TLS handshake completed
const serverTlsSocketGetPeerFinished = (async () => {
  await serverTlsSocketGetFinished;
  while (true) {
    const { errored, closed } = serverTlsSocket;
    if (errored) throw errored;
    if (closed) throw new Error("serverTlsSocket closed");
    const peerFinished = serverTlsSocket.getPeerFinished();
    if (peerFinished) return peerFinished;
    await new Promise<void>((res) => setImmediate(res));
  }
})();

const serverTlsSocketGetPeerCertificate = (async () => {
  await serverTlsSocketGetPeerFinished;
  return serverTlsSocket.getPeerX509Certificate();
})();

// TODO: server should verify peer certificate

const clientTlsSocket = tlsConnect({
  socket: clientSocket,
  ca,
  cert: clientCert,
  key: clientKey,
  servername: "local.example",
});

clientTlsSocket.on("keylog", (line) => clientTlsKeyLog.write(line));
clientTlsSocket.on("session", () =>
  console.log("client got new session/TLS ticket.")
);

serverTlsSocketGetFinished.then(() =>
  console.log(
    "server got 'Client Hello', sending 'Server Hello' and certificate request for mTLS"
  )
);
serverTlsSocketGetPeerFinished.then(() =>
  console.log("server-side TLS handshake finished")
);
serverTlsSocketGetPeerCertificate.then((peerCertificate) => {
  if (!peerCertificate)
    return console.log("client did not present certificate");
  console.log(`got client peer certificate (un-verified): ${peerCertificate}`);
});

await Promise.all([
  serverTlsSocketSession,
  serverTlsSocketGetFinished,
  serverTlsSocketGetPeerFinished,
  serverTlsSocketGetPeerCertificate,
]);

const [secureHelloFromServer, secureHelloFromClient] = await Promise.all([
  new Promise<Buffer>((res, rej) => {
    clientTlsSocket.once("error", rej);
    (clientTlsSocket as Socket).once("data", (data) => {
      res(data);
      clientTlsSocket.removeListener("error", rej);
    });
  }),
  new Promise<Buffer>((res, rej) => {
    serverTlsSocket.once("error", rej);
    (serverTlsSocket as Socket).once("data", (data: Buffer) => {
      res(data);
      serverTlsSocket.removeListener("error", rej);
    });
  }),
  promisify(clientTlsSocket.write.bind(clientTlsSocket))(
    "Hello from client in TLS"
  ),
  promisify(serverTlsSocket.write.bind(serverTlsSocket))(
    "Hello from server in TLS"
  ),
]);

console.log({
  secureHelloFromServer: secureHelloFromServer.toString(),
  secureHelloFromClient: secureHelloFromClient.toString(),
});

serverTlsSocket.end();

export {};
