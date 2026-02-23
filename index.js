/**
 * Votifier Bridge for BDS (Bedrock Dedicated Server)
 * 
 * Flow:
 *   mcindex → Votifier packet → this app → stores vote in memory queue
 *   BDS ScriptAPI → polls GET /votes every 30s → gets pending usernames → marks as claimed
 * 
 * Deploy on Railway. Set these environment variables:
 *   VOTIFIER_TOKEN  = a secret token (make something up, put same value in mcindex)
 *   POLL_SECRET     = another secret (put same value in your ScriptAPI pack)
 *   PORT            = Railway sets this automatically
 */

const net  = require('net');
const http = require('http');
const crypto = require('crypto');

const VOTIFIER_PORT  = parseInt(process.env.VOTIFIER_PORT || '8192');
const VOTIFIER_TOKEN = process.env.VOTIFIER_TOKEN || 'changeme-set-in-railway-vars';
const POLL_SECRET    = process.env.POLL_SECRET    || 'changeme-set-in-railway-vars';
const HTTP_PORT      = parseInt(process.env.PORT  || '3000');

// ─── Pending vote queue ───────────────────────────────────────────────────────
// { username, service, timestamp, claimed }
const voteQueue = [];

// ─── Votifier v2 packet parser ────────────────────────────────────────────────
function parseVotifierV2(data) {
    try {
        // Magic bytes 0x733A
        if (data.length < 4 || data[0] !== 0x73 || data[1] !== 0x3A) return null;
        const len     = data.readUInt16BE(2);
        const payload = JSON.parse(data.slice(4, 4 + len).toString('utf8'));
        return payload; // { username, serviceName, address, timestamp }
    } catch (_) { return null; }
}

// ─── Try every known format to get a username ────────────────────────────────
function extractVote(data) {
    // Try v2
    const v2 = parseVotifierV2(data);
    if (v2?.username) return { username: v2.username, service: v2.serviceName || 'unknown' };

    // Try plaintext (some test senders)
    const str = data.toString('utf8');
    const m   = str.match(/VOTE\r?\n[^\r\n]+\r?\n([^\r\n]+)/);
    if (m) return { username: m[1].trim(), service: 'unknown' };

    return null;
}

// ─── Votifier TCP server ──────────────────────────────────────────────────────
const votifier = net.createServer((socket) => {
    console.log(`[VOTIFIER] Connection from ${socket.remoteAddress}`);

    // Handshake — voting sites expect this exact format
    const challenge = crypto.randomBytes(16).toString('hex');
    socket.write(`VOTIFIER 2.9 ${challenge}\n`);

    socket.setTimeout(8000);
    const chunks = [];

    socket.on('data',    c  => chunks.push(c));
    socket.on('timeout', () => socket.destroy());
    socket.on('error',   e  => console.error('[VOTIFIER] socket error:', e.message));

    socket.on('end', () => {
        const data = Buffer.concat(chunks);
        const vote = extractVote(data);

        if (!vote) {
            console.warn(`[VOTIFIER] Unreadable packet (${data.length} bytes)`);
            console.warn('[VOTIFIER] Raw (hex):', data.slice(0, 64).toString('hex'));
            return;
        }

        console.log(`[VOTE] ${vote.username} voted via ${vote.service}`);
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
// GET  /votes?secret=XXX        → returns unclaimed votes, marks them claimed
// GET  /health                  → status check
// POST /test?secret=XXX&user=XX → manually inject a test vote

const httpServer = http.createServer((req, res) => {
    const url    = new URL(req.url, `http://localhost`);
    const secret = url.searchParams.get('secret');

    // ── Health check (no auth needed) ────────────────────────────────────────
    if (url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status:   'ok',
            uptime:   Math.floor(process.uptime()),
            queued:   voteQueue.filter(v => !v.claimed).length,
            total:    voteQueue.length
        }));
        return;
    }

    // ── Auth check for all other endpoints ───────────────────────────────────
    if (secret !== POLL_SECRET) {
        res.writeHead(401);
        res.end('Unauthorized');
        return;
    }

    // ── GET /votes — BDS polls this ──────────────────────────────────────────
    if (req.method === 'GET' && url.pathname === '/votes') {
        const unclaimed = voteQueue.filter(v => !v.claimed);
        unclaimed.forEach(v => v.claimed = true);

        // Clean up old claimed votes (keep last 500)
        while (voteQueue.length > 500) voteQueue.shift();

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(unclaimed.map(v => ({
            username:  v.username,
            service:   v.service,
            timestamp: v.timestamp
        }))));
        console.log(`[POLL] Returned ${unclaimed.length} vote(s)`);
        return;
    }

    // ── POST /test — inject a test vote manually ──────────────────────────────
    if (req.method === 'GET' && url.pathname === '/test') {
        const user = url.searchParams.get('user') || 'TestPlayer';
        voteQueue.push({
            username:  user,
            service:   'manual-test',
            timestamp: Date.now(),
            claimed:   false
        });
        console.log(`[TEST] Injected test vote for ${user}`);
        res.writeHead(200);
        res.end(`Queued test vote for ${user}`);
        return;
    }

    res.writeHead(404);
    res.end('Not found');
});

httpServer.listen(HTTP_PORT, () => {
    console.log(`[HTTP] Listening on :${HTTP_PORT}`);
    console.log(`[HTTP] Poll endpoint: GET /votes?secret=YOUR_POLL_SECRET`);
    console.log(`[HTTP] Health check:  GET /health`);
    console.log(`[HTTP] Test vote:     POST /test?secret=YOUR_POLL_SECRET&user=PlayerName`);
});

console.log('[Votifier Bridge] Ready!');
