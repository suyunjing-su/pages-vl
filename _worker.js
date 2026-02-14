import { connect } from 'cloudflare:sockets';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

const globalConfig = {
  userID: '3eab6f1a-0e0b-437a-a223-32c03b9167d2',
  openWSOutboundTimeout: 10000,
  outbounds: [],
};

export default {
  async fetch(request, env) {
    try {
      setConfigFromEnv(env);

      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        const url = new URL(request.url);
        if (url.pathname === '/') {
          return new Response('VLESS Proxy Server', { status: 200 });
        }

        if (url.pathname === `/${globalConfig.userID}`) {
          const host = request.headers.get('Host');
          const vlessConfig = `vless://${globalConfig.userID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=/#${host}`;
          return new Response(vlessConfig, {
            status: 200,
            headers: { 'Content-Type': 'text/plain;charset=utf-8' },
          });
        }

        return new Response('Not Found', { status: 404 });
      }

      return await handleVLESSWebSocket(request);
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

async function handleVLESSWebSocket(request) {
  const wsPair = new WebSocketPair();
  const [clientWS, serverWS] = Object.values(wsPair);

  serverWS.accept();

  let logPrefix = 'ws';
  function log() {
    const prefix = '[' + logPrefix + ']';
    const args = Array.prototype.slice.call(arguments);
    console.log.apply(console, [prefix].concat(args));
  }

  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  const earlyData = base64ToUint8Array(earlyDataHeader);
  const wsReadable = makeReadableWebSocketStream(serverWS, earlyData, null, log);

  let remoteTrafficSink = null;

  wsReadable.pipeTo(new WritableStream({
    async write(chunk) {
      if (remoteTrafficSink) {
        const writer = remoteTrafficSink.getWriter();
        await writer.write(chunk);
        writer.releaseLock();
        return;
      }

      const result = parseVLESSHeader(chunk, globalConfig.userID);
      if (result.hasError) {
        throw new Error(result.message);
      }

      logPrefix = `${result.addressRemote}:${result.portRemote} ${result.isUDP ? 'UDP' : 'TCP'}`;

      const vlessRespHeader = new Uint8Array([result.vlessVersion[0], 0]);
      const rawClientData = chunk.slice(result.rawDataIndex);

      const attempts = await buildOutboundAttempts(result, rawClientData, log);
      if (attempts.length === 0) {
        safeCloseWebSocket(serverWS);
        return;
      }

      remoteTrafficSink = await tryOutbounds(attempts, result, rawClientData, serverWS, vlessRespHeader, log);
    },
    close() {
      if (remoteTrafficSink) {
        try {
          remoteTrafficSink.close();
        } catch (err) {
          log('Remote sink close failed', err);
        }
      }
    }
  })).catch(err => {
    log('WebSocket error', err);
    safeCloseWebSocket(serverWS);
  });

  return new Response(null, {
    status: 101,
    webSocket: clientWS,
  });
}

function setConfigFromEnv(env) {
  globalConfig.userID = env.UUID || globalConfig.userID;

  globalConfig.outbounds = [
    { protocol: 'freedom' }
  ];

  if (env.PROXYIP) {
    const forward = {
      protocol: 'forward',
      address: env.PROXYIP,
      portMap: {},
    };

    if (env.PORTMAP) {
      try {
        forward.portMap = JSON.parse(env.PORTMAP);
      } catch (err) {
        console.log('Invalid PORTMAP JSON', err);
      }
    }

    globalConfig.outbounds.push(forward);
  }

  if (env.VLESS) {
    try {
      const { uuid, remoteHost, remotePort, queryParams } = parseVlessString(env.VLESS);
      const vless = {
        address: remoteHost,
        port: remotePort,
        users: [
          { id: uuid }
        ]
      };

      const streamSettings = {
        network: queryParams.type,
        security: queryParams.security,
      };

      if (queryParams.type === 'ws') {
        streamSettings.wsSettings = {
          headers: { Host: remoteHost },
          path: decodeURIComponent(queryParams.path || '/'),
        };
      }

      if (queryParams.security === 'tls') {
        streamSettings.tlsSettings = {
          serverName: remoteHost,
          allowInsecure: false,
        };
      }

      globalConfig.outbounds.push({
        protocol: 'vless',
        settings: { vnext: [vless] },
        streamSettings: streamSettings,
      });
    } catch (err) {
      console.log(err.toString());
    }
  }

  if (env.SOCKS5) {
    try {
      const { username, password, hostname, port } = socks5AddressParser(env.SOCKS5);
      const socks = {
        address: hostname,
        port: port,
      };

      if (typeof username !== 'undefined' && typeof password !== 'undefined') {
        socks.users = [{ user: username, pass: password }];
      }

      globalConfig.outbounds.push({
        protocol: 'socks',
        settings: { servers: [socks] },
      });
    } catch (err) {
      console.log(err.toString());
    }
  }
}

function getOutbound(protocol) {
  return globalConfig.outbounds.find(outbound => outbound.protocol === protocol) || null;
}

async function buildOutboundAttempts(vlessRequest, rawClientData, log) {
  const attempts = [];
  const vlessOutbound = getOutbound('vless');
  const socksOutbound = getOutbound('socks');
  const forwardOutbound = getOutbound('forward');

  if (vlessRequest.isUDP) {
    if (vlessOutbound) {
      attempts.push({
        name: 'vless',
        handler: () => vlessOutboundConnect(vlessOutbound, vlessRequest, rawClientData, log),
      });
    }
    return attempts;
  }

  const isIPv4 = isIPv4Address(vlessRequest.addressRemote);
  const isIPv6 = isIPv6Address(vlessRequest.addressRemote);

  if (isIPv4) {
    attempts.push({
      name: 'direct-ipv4',
      handler: () => directOutboundConnect(vlessRequest.addressRemote, vlessRequest.portRemote, rawClientData, log),
    });
    if (vlessOutbound) {
      attempts.push({
        name: 'vless',
        handler: () => vlessOutboundConnect(vlessOutbound, vlessRequest, rawClientData, log),
      });
    }
    if (socksOutbound) {
      attempts.push({
        name: 'socks5',
        handler: () => socksOutboundConnect(socksOutbound, vlessRequest, rawClientData, log),
      });
    }
    const nat64Address = convertToNAT64IPv6(vlessRequest.addressRemote);
    if (nat64Address) {
      attempts.push({
        name: 'nat64',
        handler: () => directOutboundConnect(nat64Address, vlessRequest.portRemote, rawClientData, log),
      });
    }
    return attempts;
  }

  if (isIPv6) {
    attempts.push({
      name: 'direct-ipv6',
      handler: () => directOutboundConnect(vlessRequest.addressRemote, vlessRequest.portRemote, rawClientData, log),
    });
    if (vlessOutbound) {
      attempts.push({
        name: 'vless',
        handler: () => vlessOutboundConnect(vlessOutbound, vlessRequest, rawClientData, log),
      });
    }
    if (socksOutbound) {
      attempts.push({
        name: 'socks5',
        handler: () => socksOutboundConnect(socksOutbound, vlessRequest, rawClientData, log),
      });
    }
    return attempts;
  }

  const resolvedIPv4 = await resolveDomainIPv4(vlessRequest.addressRemote);
  const resolvedIPv6 = await resolveDomainIPv6(vlessRequest.addressRemote);

  if (resolvedIPv4) {
    attempts.push({
      name: 'direct-domain-ipv4',
      handler: () => directOutboundConnect(resolvedIPv4, vlessRequest.portRemote, rawClientData, log),
    });
  }
  if (resolvedIPv6) {
    attempts.push({
      name: 'direct-domain-ipv6',
      handler: () => directOutboundConnect(resolvedIPv6, vlessRequest.portRemote, rawClientData, log),
    });
  }
  if (vlessOutbound) {
    attempts.push({
      name: 'vless',
      handler: () => vlessOutboundConnect(vlessOutbound, vlessRequest, rawClientData, log),
    });
  }
  if (socksOutbound) {
    attempts.push({
      name: 'socks5',
      handler: () => socksOutboundConnect(socksOutbound, vlessRequest, rawClientData, log),
    });
  }
  if (forwardOutbound) {
    attempts.push({
      name: 'proxyip',
      handler: () => forwardOutboundConnect(forwardOutbound, vlessRequest, rawClientData, log),
    });
  }
  if (resolvedIPv4) {
    const nat64Address = convertToNAT64IPv6(resolvedIPv4);
    if (nat64Address) {
      attempts.push({
        name: 'nat64',
        handler: () => directOutboundConnect(nat64Address, vlessRequest.portRemote, rawClientData, log),
      });
    }
  }

  return attempts;
}

async function tryOutbounds(attempts, vlessRequest, rawClientData, webSocket, vlessResponseHeader, log) {
  for (const attempt of attempts) {
    try {
      log(`Attempt outbound: ${attempt.name}`);
      const destRWPair = await attempt.handler();
      if (!destRWPair) {
        continue;
      }
      const hasIncomingData = await remoteSocketToWS(destRWPair.readableStream, webSocket, vlessResponseHeader, null, log);
      if (hasIncomingData) {
        return destRWPair.writableStream;
      }
    } catch (err) {
      log(`Outbound ${attempt.name} failed`, err.message || err);
    }
  }

  log('No outbound succeeded');
  safeCloseWebSocket(webSocket);
  return null;
}

async function directOutboundConnect(address, port, firstChunk, log) {
  const tcpSocket = await connect({ hostname: address, port: port });
  tcpSocket.closed.catch(error => log('direct socket closed', error.message || error));
  await writeFirstChunk(tcpSocket.writable, firstChunk);
  return {
    readableStream: tcpSocket.readable,
    writableStream: tcpSocket.writable,
  };
}

async function forwardOutboundConnect(forwardOutbound, vlessRequest, firstChunk, log) {
  let portDest = vlessRequest.portRemote;
  if (typeof forwardOutbound.portMap === 'object' && forwardOutbound.portMap[vlessRequest.portRemote] !== undefined) {
    portDest = forwardOutbound.portMap[vlessRequest.portRemote];
  }

  const tcpSocket = await connect({ hostname: forwardOutbound.address, port: portDest });
  tcpSocket.closed.catch(error => log('forward socket closed', error.message || error));
  await writeFirstChunk(tcpSocket.writable, firstChunk);
  return {
    readableStream: tcpSocket.readable,
    writableStream: tcpSocket.writable,
  };
}

async function socksOutboundConnect(socksOutbound, vlessRequest, firstChunk, log) {
  const server = socksOutbound.settings.servers[0];
  const tcpSocket = await connect({ hostname: server.address, port: server.port });
  tcpSocket.closed.catch(error => log('socks socket closed', error.message || error));
  const user = server.users && server.users.length > 0 ? server.users[0].user : undefined;
  const pass = server.users && server.users.length > 0 ? server.users[0].pass : undefined;
  await socks5Connect(tcpSocket, user, pass, vlessRequest.addressType, vlessRequest.addressRemote, vlessRequest.portRemote, log);
  await writeFirstChunk(tcpSocket.writable, firstChunk);
  return {
    readableStream: tcpSocket.readable,
    writableStream: tcpSocket.writable,
  };
}

async function vlessOutboundConnect(vlessOutbound, vlessRequest, firstChunk, log) {
  const server = vlessOutbound.settings.vnext[0];
  if (!server.users || server.users.length === 0) {
    throw new Error('Vless outbound missing users');
  }

  const vless = {
    address: server.address,
    port: server.port,
    uuid: server.users[0].id,
    streamSettings: vlessOutbound.streamSettings,
  };

  checkVlessConfig(vless.address, vless.streamSettings);

  let wsURL = vless.streamSettings.security === 'tls' ? 'wss://' : 'ws://';
  wsURL = wsURL + vless.address + ':' + vless.port;
  if (vless.streamSettings.wsSettings && vless.streamSettings.wsSettings.path) {
    wsURL = wsURL + vless.streamSettings.wsSettings.path;
  }

  const wsToVlessServer = new WebSocket(wsURL);
  const openPromise = new Promise((resolve, reject) => {
    wsToVlessServer.onopen = () => resolve();
    wsToVlessServer.onclose = (event) => reject(new Error(`Closed with code ${event.code}, reason: ${event.reason}`));
    wsToVlessServer.onerror = (error) => reject(error);
    setTimeout(() => {
      reject(new Error('Cannot open WebSocket connection, open connection timeout'));
    }, globalConfig.openWSOutboundTimeout);
  });

  try {
    await openPromise;
  } catch (err) {
    wsToVlessServer.close();
    throw err;
  }

  const writableStream = new WritableStream({
    async write(chunk) {
      wsToVlessServer.send(chunk);
    },
    close() {
      log('Vless WebSocket closed');
    },
    abort(reason) {
      log('Vless WebSocket aborted', reason);
    },
  });

  const headerStripper = (firstChunk) => {
    if (firstChunk.length < 2) {
      throw new Error('Too short vless response');
    }

    const responseVersion = firstChunk[0];
    const additionalBytes = firstChunk[1];

    if (responseVersion > 0) {
      log(`Unexpected vless version: ${responseVersion}`);
    }

    if (additionalBytes > 0) {
      log(`Ignored ${additionalBytes} byte(s) of additional response info`);
    }

    return firstChunk.slice(2 + additionalBytes);
  };

  const readableStream = makeReadableWebSocketStream(wsToVlessServer, null, headerStripper, log);
  const vlessReqHeader = makeVlessReqHeader(
    vlessRequest.isUDP ? VlessCmd.UDP : VlessCmd.TCP,
    vlessRequest.addressType,
    vlessRequest.addressRemote,
    vlessRequest.portRemote,
    vless.uuid
  );

  await writeFirstChunk(writableStream, joinUint8Array(vlessReqHeader, firstChunk));

  return {
    readableStream,
    writableStream,
  };
}

async function writeFirstChunk(writableStream, firstChunk) {
  const writer = writableStream.getWriter();
  await writer.write(firstChunk);
  writer.releaseLock();
}

function makeReadableWebSocketStream(webSocketServer, earlyData, headStripper, log) {
  let readableStreamCancel = false;
  let headStripped = false;

  return new ReadableStream({
    start(controller) {
      if (earlyData && earlyData.byteLength > 0) {
        controller.enqueue(earlyData);
      }

      webSocketServer.addEventListener('message', (event) => {
        if (readableStreamCancel) {
          return;
        }

        let message = new Uint8Array(event.data);
        if (!headStripped) {
          headStripped = true;
          if (headStripper != null) {
            try {
              message = headStripper(message);
            } catch (err) {
              readableStreamCancel = true;
              controller.error(err);
              return;
            }
          }
        }

        controller.enqueue(message);
      });

      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => {
        log('WebSocket error', err.message || err);
        controller.error(err);
      });
    },
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream canceled: ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    }
  });
}

function base64ToUint8Array(base64Str) {
  if (!base64Str) {
    return new Uint8Array(0);
  }

  try {
    const input = base64Str.replace(/-/g, '+').replace(/_/g, '/');
    const decode = atob(input);
    return Uint8Array.from(decode, (c) => c.charCodeAt(0));
  } catch (error) {
    return new Uint8Array(0);
  }
}

function parseVLESSHeader(buffer, userID) {
  // 最小头部长度：1(版本) + 16(UUID) + 1(附加信息长度) + 1(命令) + 2(端口) + 1(地址类型) + 1(地址长度) + 1(最小地址)
  if (buffer.byteLength < 24) {
    return { hasError: true, message: '无效的头部长度' };
  }
  
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1));
  
  // 验证 UUID
  const uuid = formatUUID(new Uint8Array(buffer.slice(1, 17)));
  if (uuid !== userID) {
    return { hasError: true, message: '无效的用户' };
  }
  
  const optionsLength = view.getUint8(17);
  const command = view.getUint8(18 + optionsLength);
  
  // 支持 TCP 和 UDP 命令
  let isUDP = false;
  if (command === 1) {
    // TCP
  } else if (command === 2) {
    // UDP
    isUDP = true;
  } else {
    return { hasError: true, message: '不支持的命令，仅支持TCP(01)和UDP(02)' };
  }
  
  let offset = 19 + optionsLength;
  const port = view.getUint16(offset);
  offset += 2;
  
  // 解析地址
  const addressType = view.getUint8(offset++);
  let address = '';
  
  switch (addressType) {
    case 1: // IPv4
      address = Array.from(new Uint8Array(buffer.slice(offset, offset + 4))).join('.');
      offset += 4;
      break;
      
    case 2: // 域名
      const domainLength = view.getUint8(offset++);
      address = new TextDecoder().decode(buffer.slice(offset, offset + domainLength));
      offset += domainLength;
      break;
      
    case 3: // IPv6
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(view.getUint16(offset).toString(16).padStart(4, '0'));
        offset += 2;
      }
      address = ipv6.join(':').replace(/(^|:)0+(\w)/g, '$1$2');
      break;
      
    default:
      return { hasError: true, message: '不支持的地址类型' };
  }
  
  return {
    hasError: false,
    addressRemote: address,
    addressType,
    portRemote: port,
    rawDataIndex: offset,
    vlessVersion: version,
    isUDP
  };
}

async function remoteSocketToWS(remoteSocketReader, webSocket, vlessResponseHeader, vlessResponseProcessor, log) {
  const toRemotePromise = new Promise((resolve) => {
    let headerSent = false;
    let hasIncomingData = false;

    const vlessResponseHeaderPrepender = new TransformStream({
      transform(chunk, controller) {
        hasIncomingData = true;
        resolve(true);

        if (!headerSent) {
          controller.enqueue(joinUint8Array(vlessResponseHeader, chunk));
          headerSent = true;
        } else {
          controller.enqueue(chunk);
        }
      },
      flush() {
        resolve(hasIncomingData);
      }
    });

    const toClientWsSink = new WritableStream({
      write(chunk, controller) {
        if (webSocket.readyState !== WS_READY_STATE_OPEN) {
          controller.error('webSocket is not open');
        }
        webSocket.send(chunk);
      },
      close() {
      }
    });

    const vlessResponseWithHeader = remoteSocketReader.pipeThrough(vlessResponseHeaderPrepender);
    const processedVlessResponse = vlessResponseProcessor == null ? vlessResponseWithHeader :
      vlessResponseWithHeader.pipeThrough(vlessResponseProcessor());

    processedVlessResponse.pipeTo(toClientWsSink)
      .catch((error) => {
        log('remoteSocketToWS error', error.stack || error);
        safeCloseWebSocket(webSocket);
      });
  });

  return await toRemotePromise;
}

function formatUUID(bytes) {
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

const VlessCmd = {
  TCP: 1,
  UDP: 2,
  MUX: 3,
};

const VlessAddrType = {
  IPv4: 1,
  DomainName: 2,
  IPv6: 3,
};

function joinUint8Array(array1, array2) {
  const result = new Uint8Array(array1.byteLength + array2.byteLength);
  result.set(array1);
  result.set(array2, array1.byteLength);
  return result;
}

function concatUint8Arrays(parts) {
  let totalLength = 0;
  for (const part of parts) {
    totalLength += part.length;
  }

  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function makeVlessReqHeader(command, destType, destAddr, destPort, uuid) {
  let addressFieldLength;
  let addressEncoded;

  switch (destType) {
    case VlessAddrType.IPv4:
      addressFieldLength = 4;
      break;
    case VlessAddrType.DomainName:
      addressEncoded = new TextEncoder().encode(destAddr);
      addressFieldLength = addressEncoded.length + 1;
      break;
    case VlessAddrType.IPv6:
      addressFieldLength = 16;
      break;
    default:
      throw new Error(`Unknown address type: ${destType}`);
  }

  const uuidString = uuid.replace(/-/g, '');
  const uuidOffset = 1;
  const vlessHeader = new Uint8Array(22 + addressFieldLength);

  vlessHeader[0] = 0x00;

  for (let i = 0; i < uuidString.length; i += 2) {
    vlessHeader[uuidOffset + i / 2] = parseInt(uuidString.substr(i, 2), 16);
  }

  vlessHeader[17] = 0x00;
  vlessHeader[18] = command;
  vlessHeader[19] = destPort >> 8;
  vlessHeader[20] = destPort & 0xFF;
  vlessHeader[21] = destType;

  switch (destType) {
    case VlessAddrType.IPv4: {
      const octetsIPv4 = destAddr.split('.');
      for (let i = 0; i < 4; i++) {
        vlessHeader[22 + i] = parseInt(octetsIPv4[i]);
      }
      break;
    }
    case VlessAddrType.DomainName:
      addressEncoded = addressEncoded;
      vlessHeader[22] = addressEncoded.length;
      vlessHeader.set(addressEncoded, 23);
      break;
    case VlessAddrType.IPv6: {
      const groupsIPv6 = destAddr.replace(/\[|\]/g, '').split(':');
      for (let i = 0; i < 8; i++) {
        const hexGroup = parseInt(groupsIPv6[i], 16);
        vlessHeader[i * 2 + 22] = hexGroup >> 8;
        vlessHeader[i * 2 + 23] = hexGroup & 0xFF;
      }
      break;
    }
    default:
      throw new Error(`Unknown address type: ${destType}`);
  }

  return vlessHeader;
}

function checkVlessConfig(address, streamSettings) {
  if (streamSettings.network !== 'ws') {
    throw new Error(`Unsupported outbound stream method: ${streamSettings.network}`);
  }

  if (streamSettings.security !== 'tls' && streamSettings.security !== 'none') {
    throw new Error(`Unsupported security layer: ${streamSettings.security}`);
  }

  if (streamSettings.wsSettings && streamSettings.wsSettings.headers && streamSettings.wsSettings.headers.Host !== address) {
    throw new Error('Host header does not match server address');
  }

  if (streamSettings.tlsSettings && streamSettings.tlsSettings.serverName !== address) {
    throw new Error('TLS SNI does not match server address');
  }
}

async function socks5Connect(socket, username, password, addressType, addressRemote, portRemote, log) {
  const writer = socket.writable.getWriter();

  await writer.write(new Uint8Array([5, 2, 0, 2]));

  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();
  let res = (await reader.read()).value;
  if (!res) {
    throw new Error('No response from the server');
  }

  if (res[0] !== 0x05) {
    throw new Error(`Wrong server version: ${res[0]} expected: 5`);
  }
  if (res[1] === 0xff) {
    throw new Error('No accepted authentication methods');
  }

  if (res[1] === 0x02) {
    log('Socks5: Server asks for authentication');
    if (!username || !password) {
      throw new Error('Please provide username/password');
    }
    const userBytes = encoder.encode(username);
    const passBytes = encoder.encode(password);
    const authRequest = concatUint8Arrays([
      new Uint8Array([1, userBytes.length]),
      userBytes,
      new Uint8Array([passBytes.length]),
      passBytes,
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (typeof res === 'undefined' || res[0] !== 0x01 || res[1] !== 0x00) {
      throw new Error('Authentication failed');
    }
  }

  let dstAddr;
  switch (addressType) {
    case 1:
      {
        const octets = addressRemote.split('.').map(Number);
        dstAddr = new Uint8Array(1 + octets.length);
        dstAddr[0] = 1;
        dstAddr.set(octets, 1);
      }
      break;
    case 2:
      {
        const addrBytes = encoder.encode(addressRemote);
        dstAddr = new Uint8Array(2 + addrBytes.length);
        dstAddr[0] = 3;
        dstAddr[1] = addrBytes.length;
        dstAddr.set(addrBytes, 2);
      }
      break;
    case 3:
      {
        const groups = addressRemote.split(':');
        const bytes = [];
        for (const group of groups) {
          const padded = group.padStart(4, '0');
          const high = parseInt(padded.slice(0, 2), 16);
          const low = parseInt(padded.slice(2), 16);
          bytes.push(high, low);
        }
        dstAddr = new Uint8Array(1 + bytes.length);
        dstAddr[0] = 4;
        dstAddr.set(bytes, 1);
      }
      break;
    default:
      log(`Invalid addressType ${addressType}`);
      return;
  }

  const socksRequest = new Uint8Array(3 + dstAddr.length + 2);
  socksRequest[0] = 5;
  socksRequest[1] = 1;
  socksRequest[2] = 0;
  socksRequest.set(dstAddr, 3);
  socksRequest[3 + dstAddr.length] = portRemote >> 8;
  socksRequest[4 + dstAddr.length] = portRemote & 0xff;
  await writer.write(socksRequest);
  log('Socks5: Sent request');

  res = (await reader.read()).value;
  if (typeof res !== 'undefined' && res[1] === 0x00) {
    log('Socks5: Connection opened');
  } else {
    throw new Error('Connection failed');
  }

  writer.releaseLock();
  reader.releaseLock();
}

function socks5AddressParser(address) {
  const [latter, former] = address.split('@').reverse();
  let username, password;
  if (former) {
    const formers = former.split(':');
    if (formers.length !== 2) {
      throw new Error('Invalid SOCKS address format');
    }
    [username, password] = formers;
  }
  const latters = latter.split(':');
  const port = Number(latters.pop());
  if (isNaN(port)) {
    throw new Error('Invalid SOCKS address format');
  }
  const hostname = latters.join(':');
  const regex = /^\[.*\]$/;
  if (hostname.includes(':') && !regex.test(hostname)) {
    throw new Error('Invalid SOCKS address format');
  }
  return {
    username,
    password,
    hostname,
    port,
  };
}

function parseVlessString(url) {
  const regex = /^(.+):\/\/(.+?)@(.+?):(\d+)(\?[^#]*)?(#.*)?$/;
  const match = url.match(regex);

  if (!match) {
    throw new Error('Invalid URL format');
  }

  const [, protocol, uuid, remoteHost, remotePort, query, descriptiveText] = match;

  const json = {
    protocol,
    uuid,
    remoteHost,
    remotePort: parseInt(remotePort),
    descriptiveText: descriptiveText ? descriptiveText.substring(1) : '',
    queryParams: {}
  };

  if (query) {
    const queryFields = query.substring(1).split('&');
    queryFields.forEach(field => {
      const [key, value] = field.split('=');
      json.queryParams[key] = value;
    });
  }

  return json;
}

function isIPv4Address(value) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

function isIPv6Address(value) {
  return /^[0-9a-fA-F:]+$/.test(value) && value.includes(':');
}

async function resolveDomainIPv4(domain) {
  try {
    const result = await fetchDnsJson(`https://dns.google/resolve?name=${domain}&type=A`);
    const answer = result.Answer && result.Answer.find(record => record.type === 1);
    return answer ? answer.data : null;
  } catch (err) {
    return null;
  }
}

async function resolveDomainIPv6(domain) {
  try {
    const result = await fetchDnsJson(`https://dns.google/resolve?name=${domain}&type=AAAA`);
    const answer = result.Answer && result.Answer.find(record => record.type === 28);
    return answer ? answer.data : null;
  } catch (err) {
    return null;
  }
}

async function fetchDnsJson(url) {
  const resp = await fetch(url, {
    headers: { 'Accept': 'application/dns-json' }
  });
  const bodyText = await resp.text();

  if (!resp.ok) {
    const snippet = bodyText.slice(0, 120);
    throw new Error(`DoH response error: ${resp.status} ${snippet}`);
  }

  try {
    return JSON.parse(bodyText);
  } catch (err) {
    const snippet = bodyText.slice(0, 120);
    throw new Error(`DoH parse error: ${snippet}`);
  }
}

function convertToNAT64IPv6(ipv4Address) {
  const parts = ipv4Address.split('.');
  if (parts.length !== 4) {
    return null;
  }

  const hex = parts.map(part => {
    const num = parseInt(part, 10);
    if (num < 0 || num > 255) {
      throw new Error('Invalid IPv4 segment');
    }
    return num.toString(16).padStart(2, '0');
  });

  return `2602:fc59:11:64::${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error', error);
  }
}
