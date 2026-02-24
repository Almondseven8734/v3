const net    = require('net');
const http   = require('http');
const crypto = require('crypto');

const VOTIFIER_PORT = parseInt(process.env.VOTIFIER_PORT || '28967');
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

const voteQueue = [];

function decryptV1(buffer) {
    try {
        return crypto.privateDecrypt(
            { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
            buffer
        ).toString('utf8');
    } catch (_) { return null; }
}

function parseV2(data, challenge) {
    try {
        if (data[0] !== 0x73 || data[1] !== 0x3A) return null;
        const len = data.readUInt16BE(2);
        const payload = JSON.parse(data.slice(4, 4 + len).toString('utf8'));
        // Verify HMAC signature if challenge provided
        if (challenge && payload.signature) {
            const sigLen = data.readUInt16BE(4 + len);
            const sig = data.slice(6 + len, 6 + len + sigLen).toString('base64');
            const expected = crypto.createHmac('sha256', POLL_SECRET)
                .update(JSON.stringify(payload))
                .digest('base64');
            // Don't reject on sig mismatch — just log it
            if (sig !== expected) {
                console.warn('[VOTIFIER] HMAC mismatch (still accepting)');
            }
        }
        return payload;
    } catch (_) { return null; }
}

function extractVote(data, challenge) {
    // Try v2
    const v2 = parseV2(data, challenge);
    if (v2 && v2.username) return { username: v2.username, service: v2.serviceName || 'unknown' };

    // Try v1 RSA on various sizes
    for (const size of [data.length, 256, 128]) {
        if (data.length >= size && size >= 128) {
            const dec = decryptV1(data.slice(0, size));
            if (dec) {
                const parts = dec.split('\n');
                if (parts[0] === 'VOTE' && parts[2]) {
                    return { username: parts[2].trim(), service: parts[1] || 'unknown' };
                }
            }
        }
    }

    return null;
}

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

// ─── Votifier TCP server ──────────────────────────────────────────────────────
const votifier = net.createServer((socket) => {
    console.log(`[VOTIFIER] Connection from ${socket.remoteAddress}`);

    const challenge = crypto.randomBytes(16).toString('hex');
    const handshakeJson = JSON.stringify({ v: '2.9', challenge });
    socket.write(`VOTIFIER 2.9 ${handshakeJson}\n`);

    socket.setTimeout(10000);
    const chunks = [];
    socket.on('data', c => {
        chunks.push(c);
        console.log(`[VOTIFIER] Received chunk: ${c.length} bytes`);
    });
    socket.on('timeout', () => {
        console.warn('[VOTIFIER] Connection timed out');
        socket.destroy();
    });
    socket.on('error', e => console.error('[VOTIFIER] socket error:', e.message));
    socket.on('end', () => {
        const data = Buffer.concat(chunks);
        console.log(`[VOTIFIER] Packet complete: ${data.length} bytes`);
        if (data.length > 0) {
            console.log(`[VOTIFIER] Hex: ${data.slice(0, 64).toString('hex')}`);
            console.log(`[VOTIFIER] UTF8: ${data.slice(0, 200).toString('utf8').replace(/[^\x20-\x7E]/g, '?')}`);
        }
        const vote = extractVote(data, challenge);
        if (!vote) { console.warn(`[VOTIFIER] Could not parse packet (${data.length} bytes)`); return; }
        console.log(`[VOTE] ${vote.username} voted!`);
        voteQueue.push({ username: vote.username, service: vote.service, timestamp: Date.now(), claimed: false });
    });
});

votifier.listen(VOTIFIER_PORT, '0.0.0.0', () => console.log(`[VOTIFIER] Listening on :${VOTIFIER_PORT}`));
votifier.on('error', e => {
    console.error('[VOTIFIER] server error:', e.message);
    if (e.code === 'EADDRINUSE') {
        console.log('[VOTIFIER] Port busy, retrying in 3s...');
        setTimeout(() => {
            votifier.close();
            votifier.listen(VOTIFIER_PORT, '0.0.0.0', () => console.log(`[VOTIFIER] Listening on :${VOTIFIER_PORT}`));
        }, 3000);
    }
});

console.log('[Votifier Bridge] Started!');
