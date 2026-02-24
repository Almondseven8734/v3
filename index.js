const net    = require('net');
const http   = require('http');
const crypto = require('crypto');

const VOTIFIER_PORT = parseInt(process.env.VOTIFIER_PORT || '7001');
const POLL_SECRET   = process.env.POLL_SECRET || 'changeme';
const HTTP_PORT     = parseInt(process.env.PORT || '8080');

// ─── Generate RSA key pair on startup ────────────────────────────────────────
console.log('[KEYS] Generating RSA key pair...');
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'spki',  format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});
console.log('[KEYS] Done.');
console.log('[KEYS] Public key:');
console.log(publicKey);

// ─── Vote queue ───────────────────────────────────────────────────────────────
const voteQueue = [];

// ─── Decrypt Votifier v1 ──────────────────────────────────────────────────────
function decryptV1(buffer) {
    try {
        return crypto.privateDecrypt(
            { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
            buffer
        ).toString('utf8');
    } catch (_) { return null; }
}

// ─── Parse Votifier v2 ────────────────────────────────────────────────────────
function parseV2(data) {
    try {
        if (data[0] !== 0x73 || data[1] !== 0x3A) return null;
        const len = data.readUInt16BE(2);
        return JSON.parse(data.slice(4, 4 + len).toString('utf8'));
    } catch (_) { return null; }
}

// ─── Extract vote ─────────────────────────────────────────────────────────────
function extractVote(data) {
    const v2 = parseV2(data);
    if (v2?.username) return { username: v2.username, service: v2.serviceName || 'unknown' };

    if (data.length >= 256) {
        const dec = decryptV1(data.slice(0, 256));
        if (dec) {
            const parts = dec.split('\n');
            if (parts[0] === 'VOTE' && parts[2]) return { username: parts[2].trim(), service: parts[1] || 'unknown' };
        }
    }
    return null;
}

// ─── Votifier TCP server ──────────────────────────────────────────────────────
const votifier = net.createServer((socket) => {
    console.log(`[VOTIFIER] Connection from ${socket.remoteAddress}`);
    socket.write(`VOTIFIER 2.9 ${crypto.randomBytes(8).toString('hex')}\n`);
    socket.setTimeout(8000);
    const chunks = [];
    socket.on('data', c => chunks.push(c));
    socket.on('timeout', () => socket.destroy());
    socket.on('error', e => console.error('[VOTIFIER] socket error:', e.message));
    socket.on('end', () => {
        const data = Buffer.concat(chunks);
        const vote = extractVote(data);
        if (!vote) { console.warn(`[VOTIFIER] Could not parse packet (${data.length} bytes)`); return; }
        console.log(`[VOTE] ${vote.username} voted!`);
        voteQueue.push({ username: vote.username, service: vote.service, timestamp: Date.now(), claimed: false });
    });
});
votifier.listen(VOTIFIER_PORT, '0.0.0.0', () => console.log(`[VOTIFIER] Listening on :${VOTIFIER_PORT}`));
votifier.on('error', e => console.error('[VOTIFIER] server error:', e.message));

// ─── HTTP server ──────────────────────────────────────────────────────────────
http.createServer((req, res) => {
    const url    = new URL(req.url, 'http://localhost');
    const secret = url.searchParams.get('secret');

    if (url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok', uptime: Math.floor(process.uptime()), queued: voteQueue.filter(v => !v.claimed).length }));
        return;
    }

    if (url.pathname === '/publickey') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(publicKey);
        return;
    }

    if (secret !== POLL_SECRET) { res.writeHead(401); res.end('Unauthorized'); return; }

    if (url.pathname === '/votes') {
        const unclaimed = voteQueue.filter(v => !v.claimed);
        unclaimed.forEach(v => v.claimed = true);
        while (voteQueue.length > 500) voteQueue.shift();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(unclaimed.map(v => ({ username: v.username, service: v.service, timestamp: v.timestamp }))));
        console.log(`[POLL] Returned ${unclaimed.length} vote(s)`);
        return;
    }

    if (url.pathname === '/test') {
        const user = url.searchParams.get('user') || 'TestPlayer';
        voteQueue.push({ username: user, service: 'manual-test', timestamp: Date.now(), claimed: false });
        console.log(`[TEST] Queued vote for ${user}`);
        res.writeHead(200);
        res.end(`Queued test vote for ${user}`);
        return;
    }

    res.writeHead(404);
    res.end('Not found');
}).listen(HTTP_PORT, '0.0.0.0', () => {
    console.log(`[HTTP] Listening on :${HTTP_PORT}`);
});

console.log('[Votifier Bridge] Started!');
