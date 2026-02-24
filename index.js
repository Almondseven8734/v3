const http           = require('http');
const crypto         = require('crypto');
const VotifierServer = require('votifier-server');

const POLL_SECRET    = process.env.POLL_SECRET   || 'changeme';
const HTTP_PORT      = parseInt(process.env.PORT || '8080');
const VOTIFIER_PORT  = 25000;

const voteQueue = [];

// Generate RSA keys
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding:  { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
});

console.log('[KEYS] Public key:');
console.log(publicKey);

// Start Votifier using the npm package
const votifier = new VotifierServer(privateKey, VOTIFIER_PORT);

votifier.on('vote', (vote) => {
    console.log(`[VOTE] ${vote.user} voted via ${vote.server}!`);
    voteQueue.push({
        username:  vote.user,
        service:   vote.server,
        timestamp: Date.now(),
        claimed:   false
    });
});

votifier.on('error', (err) => {
    console.error('[VOTIFIER] Error:', err.message);
});

console.log(`[VOTIFIER] Listening on :${VOTIFIER_PORT}`);

// HTTP server
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
