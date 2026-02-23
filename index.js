const net    = require('net');
const http   = require('http');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

const VOTIFIER_PORT  = parseInt(process.env.VOTIFIER_PORT || '25565');
const POLL_SECRET    = process.env.POLL_SECRET    || 'changeme';
const HTTP_PORT      = parseInt(process.env.PORT  || '8192');
const KEY_PATH       = path.join('/tmp', 'votifier_private.pem');
const PUBKEY_PATH    = path.join('/tmp', 'votifier_public.pem');

// ─── Vote queue ───────────────────────────────────────────────────────────────
const voteQueue = [];

// ─── RSA key pair (generate once, reuse) ─────────────────────────────────────
function getOrCreateKeys() {
    try {
        if (fs.existsSync(KEY_PATH) && fs.existsSync(PUBKEY_PATH)) {
            return {
                privateKey: fs.readFileSync(KEY_PATH, 'utf8'),
                publicKey:  fs.readFileSync(PUBKEY_PATH, 'utf8')
            };
        }
    } catch (_) {}

    console.log('[KEYS] Generating RSA 2048 key pair...');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding:  { type: 'spki',  format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });

    fs.writeFileSync(KEY_PATH,    privateKey,  'utf8');
    fs.writeFileSync(PUBKEY_PATH, publicKey,   'utf8');
    console.log('[KEYS] Keys generated and saved.');
    return { privateKey, publicKey };
}

const { privateKey, publicKey } = getOrCreateKeys();

// Strip PEM headers for display
const pubKeyStripped = publicKey
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\n/g, '')
    .trim();

console.log('[KEYS] Your Votifier public key (paste this into mcindex):');
console.log(publicKey);

// ─── Decrypt Votifier v1 packet ───────────────────────────────────────────────
function decryptV1(buffer) {
    try {
        const decrypted = crypto.privateDecrypt(
            { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
            buffer
        );
        return decrypted.toString('utf8');
    } catch (e) {
        return null;
    }
}

// ─── Parse Votifier v2 packet ─────────────────────────────────────────────────
function parseV2(data) {
    try {
        if (data[0] !== 0x73 || data[1] !== 0x3A) return null;
        const len     = data.readUInt16BE(2);
        const payload = JSON.parse(data.slice(4, 4 + len).toString('utf8'));
        return payload;
    } catch (_) { return null; }
}

// ─── Extract vote from any packet format ─────────────────────────────────────
function extractVote(data) {
    // Try v2 first
    const v2 = parseV2(data);
    if (v2?.username) return { username: v2.username, service: v2.serviceName || 'unknown' };

    // Try v1 RSA decryption
    if (data.length >= 256) {
        const decrypted = decryptV1(data.slice(0, 256));
        if (decrypted) {
            const parts = decrypted.split('\n');
            if (parts[0] === 'VOTE' && parts[2]) {
                return { username: parts[2].trim(), service: parts[1] || 'unknown' };
            }
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
    socket.on('data',    c  => chunks.push(c));
    socket.on('timeout', () => socket.destroy());
    socket.on('error',   e  => console.error('[VOTIFIER] error:', e.message));

    socket.on('end', () => {
        const data = Buffer.concat(chunks);
        const vote = extractVote(data);

        if (!vote) {
            console.warn(`[VOTIFIER] Could not parse packet (${data.length} bytes)`);
            return;
        }

        console.log(`[VOTE] ${vote.username} voted via ${vote.service}!`);
        voteQueue.push({
            username:  vote.username,
            service:   vote.service,
            timestamp: Date.now(),
            claimed:   false
        });
    });
});

votifier.listen(VOTIFIER_PORT, '0.0.0.0', () => {
    console.log(`[VOTIFIER] Listening on :${VOTIFIER_PORT}`);
});
votifier.on('error', e => console.error('[VOTIFIER] server error:', e.message));

// ─── HTTP server ──────────────────────────────────────────────────────────────
http.createServer((req, res) => {
    const url    = new URL(req.url, 'http://localhost');
    const secret = url.searchParams.get('secret');

    // Health / public key (no auth)
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

    // Auth required for everything else
    if (secret !== POLL_SECRET) {
        res.writeHead(401);
        res.end('Unauthorized');
        return;
    }

    if (url.pathname === '/votes') {
        const unclaimed = voteQueue.filter(v => !v.claimed);
        unclaimed.forEach(v => v.claimed = true);
        while (voteQueue.length > 500) voteQueue.shift();
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(unclaimed.map(v => ({ username: v.username, service: v.service, timestamp: v.timestamp }))));
        console.log(`[POLL] Returned ${unclaimed.length} vote(s)`);
        return;
    }

    if ((req.method === 'GET' || req.method === 'POST') && url.pathname === '/test') {
        const user = url.searchParams.get('user') || 'TestPlayer';
        voteQueue.push({ username: user, service: 'manual-test', timestamp: Date.now(), claimed: false });
        console.log(`[TEST] Injected vote for ${user}`);
        res.writeHead(200);
        res.end(`Queued test vote for ${user}`);
        return;
    }

    res.writeHead(404);
    res.end('Not found');
}).listen(HTTP_PORT, () => {
    console.log(`[HTTP] Listening on :${HTTP_PORT}`);
    console.log(`[HTTP] Public key available at: GET /publickey`);
});

console.log('[Votifier Bridge] Started!');
