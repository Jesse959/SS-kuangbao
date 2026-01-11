import { connect } from 'cloudflare:sockets';

// ============ 常量 ============
const UUID = new Uint8Array([
  0x55, 0xd9, 0xec, 0x38, 0x1b, 0x8a, 0x45, 0x4b,
  0x98, 0x1a, 0x6a, 0xcf, 0xe8, 0xf5, 0x6d, 0x8c
]);
const PROXY_HOST = 'sjc.o00o.ooo';
const PROXY_PORT = 443;

const WS_HI = 32768;
const WS_LO = 16384;
const MERGE_MAX = 16384;
const BATCH_HI = 8;
const BATCH_LO = 2;
const BP_LIMIT = 20;
const TIMEOUT = 2000;
const Q_MAX = 32;
const QB_MAX = 262144;

const DEC = new TextDecoder();
const EMPTY = new Uint8Array(0);
const VHDR = new Uint8Array([0, 0]);

const R400 = new Response(null, {status: 400});
const R403 = new Response(null, {status: 403});
const R426 = new Response(null, {status: 426, headers: {Upgrade: 'websocket'}});
const R502 = new Response(null, {status: 502});

// ============ 单态结果对象 ============
function VLESSResult() {
  this.ok = false;
  this.host = '';
  this.port = 0;
  this.off = 0;
}

const VFAIL = Object.freeze(new VLESSResult());
const B64FAIL = new Uint8Array(0);

// ============ Base64 解码 ============
function b64dec(s) {
  let bin;
  try {
    bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  } catch {
    return B64FAIL;
  }
  
  const len = bin.length | 0;
  if (len === 0) return B64FAIL;
  
  const out = new Uint8Array(len);
  const end8 = (len & ~7) | 0;
  
  let i = 0;
  while (i < end8) {
    out[i] = bin.charCodeAt(i) | 0;
    out[i+1] = bin.charCodeAt(i+1) | 0;
    out[i+2] = bin.charCodeAt(i+2) | 0;
    out[i+3] = bin.charCodeAt(i+3) | 0;
    out[i+4] = bin.charCodeAt(i+4) | 0;
    out[i+5] = bin.charCodeAt(i+5) | 0;
    out[i+6] = bin.charCodeAt(i+6) | 0;
    out[i+7] = bin.charCodeAt(i+7) | 0;
    i = (i + 8) | 0;
  }
  while (i < len) {
    out[i] = bin.charCodeAt(i) | 0;
    i = (i + 1) | 0;
  }
  
  return out;
}

// ============ UUID 验证 ============
function chkUUID(d, o) {
  const o0 = o | 0;
  return (
    (((d[o0] ^ UUID[0]) | (d[o0+1] ^ UUID[1]) | (d[o0+2] ^ UUID[2]) | (d[o0+3] ^ UUID[3])) | 0) === 0 &&
    (((d[o0+4] ^ UUID[4]) | (d[o0+5] ^ UUID[5]) | (d[o0+6] ^ UUID[6]) | (d[o0+7] ^ UUID[7])) | 0) === 0 &&
    (((d[o0+8] ^ UUID[8]) | (d[o0+9] ^ UUID[9]) | (d[o0+10] ^ UUID[10]) | (d[o0+11] ^ UUID[11])) | 0) === 0 &&
    (((d[o0+12] ^ UUID[12]) | (d[o0+13] ^ UUID[13]) | (d[o0+14] ^ UUID[14]) | (d[o0+15] ^ UUID[15])) | 0) === 0
  );
}

// ============ VLESS 解析（保留数组 join - 已验证更快） ============
function parseVL(d) {
  const result = new VLESSResult();
  const len = d.length | 0;
  
  if (len < 22 || d[0] !== 0) return VFAIL;
  if (!chkUUID(d, 1)) return VFAIL;
  
  const alen = d[17] | 0;
  if (alen > 255) return VFAIL;
  
  const coff = (18 + alen) | 0;
  if ((coff + 3) > len) return VFAIL;
  if (d[coff] !== 1) return VFAIL;
  
  const port = ((d[coff+1] << 8) | d[coff+2]) | 0;
  const aoff = (coff + 3) | 0;
  if (aoff >= len) return VFAIL;
  
  const atype = d[aoff] | 0;
  let host = '';
  let end = 0;
  
  if (atype === 1) {
    end = (aoff + 5) | 0;
    if (end > len) return VFAIL;
    const a = d[aoff+1] | 0;
    const b = d[aoff+2] | 0;
    const c = d[aoff+3] | 0;
    const e = d[aoff+4] | 0;
    host = `${a}.${b}.${c}.${e}`;
  } else if (atype === 2) {
    if ((aoff + 2) > len) return VFAIL;
    const dlen = d[aoff+1] | 0;
    end = (aoff + 2 + dlen) | 0;
    if (end > len) return VFAIL;
    host = DEC.decode(d.subarray(aoff + 2, end));
  } else if (atype === 3) {
    end = (aoff + 17) | 0;
    if (end > len) return VFAIL;
    const v = new DataView(d.buffer, d.byteOffset + aoff + 1, 16);
    // 保留数组 join - 单次分配，单次拼接
    const parts = new Array(8);
    parts[0] = v.getUint16(0).toString(16);
    parts[1] = v.getUint16(2).toString(16);
    parts[2] = v.getUint16(4).toString(16);
    parts[3] = v.getUint16(6).toString(16);
    parts[4] = v.getUint16(8).toString(16);
    parts[5] = v.getUint16(10).toString(16);
    parts[6] = v.getUint16(12).toString(16);
    parts[7] = v.getUint16(14).toString(16);
    host = parts.join(':');
  } else {
    return VFAIL;
  }
  
  if (end > len) return VFAIL;
  
  result.ok = true;
  result.host = host;
  result.port = port;
  result.off = end;
  return result;
}

// ============ TCP 连接 ============
async function dial(host, port, fb) {
  const h = fb ? PROXY_HOST : host;
  const p = (fb ? PROXY_PORT : port) | 0;
  
  const sock = connect({hostname: h, port: p}, {allowHalfOpen: false});
  
  let tid = 0;
  try {
    await Promise.race([
      sock.opened,
      new Promise((_, rej) => { tid = setTimeout(rej, TIMEOUT) | 0; })
    ]);
  } finally {
    if (tid !== 0) clearTimeout(tid);
  }
  
  return sock;
}

// ============ 状态（固定形状，无动态方法） ============
function State(ws, tcp) {
  this.ws = ws;
  this.tcp = tcp;
  this.dead = false;
}

State.prototype.kill = function() {
  if (this.dead) return;
  this.dead = true;
  
  const ws = this.ws;
  const tcp = this.tcp;
  this.ws = null;
  this.tcp = null;
  
  queueMicrotask(() => {
    try { if (ws) ws.close(); } catch {}
    try { if (tcp) tcp.close(); } catch {}
  });
};

// ============ 上行（纯优化：窗口批量，无额外状态） ============
function Uplink(s, w) {
  this.s = s;
  this.w = w;
  this.q = [];
  this.qb = 0;
  this.lock = false;
}

Uplink.prototype.push = function(chunk) {
  const s = this.s;
  if (s.dead) return;
  
  const len = chunk.length | 0;
  const qlen = this.q.length | 0;
  const qb = this.qb | 0;
  
  if (qlen >= Q_MAX || qb > QB_MAX) {
    s.kill();
    return;
  }
  
  this.q.push(chunk);
  this.qb = (qb + len) | 0;
  
  const flush = len > 8192 || this.qb >= MERGE_MAX || qlen >= 15;
  
  if (!this.lock && flush) {
    this.drain();
  } else if (!this.lock) {
    const self = this;
    queueMicrotask(() => self.drain());
  }
};

Uplink.prototype.drain = async function() {
  if (this.lock || this.s.dead || this.q.length === 0) return;
  
  this.lock = true;
  const s = this.s;
  const w = this.w;
  const q = this.q;
  
  while (q.length > 0 && !s.dead) {
    const qlen = q.length | 0;
    
    let bc = 0;
    let bb = 0;
    
    for (let i = 0; i < qlen && bc < 16; i = (i + 1) | 0) {
      const clen = q[i].length | 0;
      if (bb > 0 && (bb + clen) > MERGE_MAX) break;
      bb = (bb + clen) | 0;
      bc = (bc + 1) | 0;
    }
    
    const batch = q.splice(0, bc);
    this.qb = (this.qb - bb) | 0;
    
    let data;
    if (bc === 1) {
      data = batch[0];
    } else {
      data = new Uint8Array(bb);
      let off = 0;
      for (let i = 0; i < bc; i = (i + 1) | 0) {
        const c = batch[i];
        data.set(c, off);
        off = (off + c.length) | 0;
      }
    }
    
    try {
      await w.ready;
      if (s.dead) break;
      await w.write(data);
    } catch {
      s.kill();
      break;
    }
  }
  
  this.lock = false;
};

// ============ 下行（纯优化：限制轮询，无缓冲池） ============
function Downlink(s, ws, r) {
  this.s = s;
  this.ws = ws;
  this.r = r;
  this.first = true;
  this.run();
}

Downlink.prototype.run = async function() {
  const s = this.s;
  const ws = this.ws;
  const r = this.r;
  let first = this.first;
  
  try {
    while (!s.dead) {
      let buf = ws.bufferedAmount | 0;
      
      if (buf > WS_HI) {
        let cnt = 0;
        await new Promise(res => {
          const chk = () => {
            if (s.dead || ws.bufferedAmount < WS_LO) {
              res();
              return;
            }
            cnt = (cnt + 1) | 0;
            if (cnt > BP_LIMIT) {
              setTimeout(res, 1);
            } else {
              queueMicrotask(chk);
            }
          };
          chk();
        });
        if (s.dead) break;
      }
      
      buf = ws.bufferedAmount | 0;
      const qt = (buf < WS_LO) ? BATCH_HI : BATCH_LO;
      
      for (let i = 0; i < qt && !s.dead; i = (i + 1) | 0) {
        const {done, value} = await r.read();
        
        if (done || s.dead) {
          s.kill();
          return;
        }
        
        if (first) {
          const vlen = value.length | 0;
          const frame = new Uint8Array((vlen + 2) | 0);
          frame.set(VHDR, 0);
          frame.set(value, 2);
          ws.send(frame);
          first = false;
        } else {
          ws.send(value);
        }
        
        buf = ws.bufferedAmount | 0;
        if (buf > WS_HI) break;
      }
    }
  } catch {
    s.kill();
  } finally {
    queueMicrotask(() => {
      try { r.releaseLock(); } catch {}
    });
  }
};

// ============ 主入口 ============
export default {
  async fetch(req) {
    if (req.headers.get('Upgrade') !== 'websocket') return R426;
    
    const proto = req.headers.get('Sec-WebSocket-Protocol');
    if (!proto) return R400;
    
    const data = b64dec(proto);
    if (data === B64FAIL) return R400;
    
    const vl = parseVL(data);
    if (!vl.ok) return R403;
    
    let tcp;
    try {
      tcp = await dial(vl.host, vl.port, false);
    } catch {
      try {
        tcp = await dial(vl.host, vl.port, true);
      } catch {
        return R502;
      }
    }
    
    const [client, server] = Object.values(new WebSocketPair());
    server.accept();
    
    const state = new State(server, tcp);
    
    const dlen = data.length | 0;
    const doff = vl.off | 0;
    const init = dlen > doff ? data.subarray(doff) : EMPTY;
    
    const writer = tcp.writable.getWriter();
    const reader = tcp.readable.getReader();
    
    const up = new Uplink(state, writer);
    if (init.length > 0) up.push(init);
    
    const onMsg = e => up.push(new Uint8Array(e.data));
    const onClose = () => state.kill();
    const onErr = () => state.kill();
    
    server.addEventListener('message', onMsg);
    server.addEventListener('close', onClose);
    server.addEventListener('error', onErr);
    
    new Downlink(state, server, reader);
    
    return new Response(null, {status: 101, webSocket: client});
  }
};
