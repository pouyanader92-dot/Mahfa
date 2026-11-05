const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// ===== تنظیمات (همان متغیرهای قبلی JSONBin؛ هیچ متغیر جدیدی اجباری نیست) =====
const BIN_ID = process.env.JSONBIN_BIN_ID;
const API_KEY = process.env.JSONBIN_API_KEY;
const BASE = process.env.JSONBIN_BASE || 'https://api.jsonbin.io/v3/b';
const DB_URL = `${BASE}/${BIN_ID}`;
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'zeynab').toLowerCase();
// اگر SESSION_SECRET ست نشده باشد، از کلید JSONBin مشتق می‌شود
const SECRET = process.env.SESSION_SECRET ||
    crypto.createHash('sha256').update('mahfa-session:' + (API_KEY || 'dev')).digest('hex');
const TOKEN_TTL_MS = 7 * 24 * 3600 * 1000;

app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'same-origin');
    next();
});
app.use(express.static(path.join(__dirname, 'public')));

class HttpError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

// ===== داده‌ی اولیه (فقط اگر Bin کاملاً خالی باشد) =====
const SEED = [
    ['zeynab','خانم زینب'],['yasinkiaei','یاسین کیایی'],['amirmohammadgoli','امیرمحمد گلی'],
    ['rezakarimpoor','رضا کریم پور'],['parhamdavoodi','پرهام داوودی'],['radinnabipoor','رادین نبی پور'],
    ['mahdihabibi','مهدی حبیبی'],['pouyanader','پویا نادر'],['zahramahmoudian','زهرا محمودیان'],
    ['fatemefazli','فاطمه فضلی'],['kianadaryabari','کیانا دریاباری'],['taranomhosseinzadeh','ترنم حسین زاده'],
    ['talmaghasemi','تلما قاسمی'],['paniyaabbaspoor','پانیا عباس پور'],['alimoosavi','علی موسوی'],
    ['farsamramazanzadeh','فرسام رمضان زاده'],['kiankarimnasab','کیان کریم نسب'],['sobhanzahedian','سبحان زاهدیان'],
    ['sorenaghasemi','سورنا قاسمی'],['zavoshghabadi','زاووش قبادی'],['mohammadahamashaykh','محمدطاها مشایخ'],
    ['samighasemzadeh','سامی قاسم زاده'],['mohammadaminafsharpoor','محمدامین افشار پور'],
    ['kasraahmadi','کسری احمدی'],['amirrezaabbasgholizadeh','امیررضا عباس قلی زاده']
];
const seedDb = () => ({
    users: SEED.map(([username, displayName]) => ({ username, displayName, points: 0, password: username === 'zeynab' ? 'admin123' : username + '123' })),
    messages: [], log: []
});

// ===== رمزها =====
async function hashPassword(pw) {
    const salt = crypto.randomBytes(16).toString('hex');
    const key = await scrypt(pw, salt, 32);
    return `scrypt$${salt}$${key.toString('hex')}`;
}
async function verifyPassword(pw, stored) {
    const [alg, salt, hex] = String(stored || '').split('$');
    if (alg !== 'scrypt' || !salt || !hex) return false;
    const key = await scrypt(pw, salt, 32);
    const expected = Buffer.from(hex, 'hex');
    return key.length === expected.length && crypto.timingSafeEqual(key, expected);
}
const DUMMY_HASH_PROMISE = hashPassword('dummy-password');
function randomPassword() {
    const chars = 'abcdefghjkmnpqrstuvwxyz23456789';
    return Array.from(crypto.randomBytes(8), b => chars[b % chars.length]).join('');
}

// مهاجرت: رمزهای متن‌ساده‌ی قبلی → هش، و تعیین نقش معلم
async function migrate(record) {
    let changed = false;
    if (!Array.isArray(record.users)) { record.users = []; changed = true; }
    if (!Array.isArray(record.messages)) { record.messages = []; changed = true; }
    if (!Array.isArray(record.log)) { record.log = []; changed = true; }
    for (const u of record.users) {
        if (typeof u.password === 'string') {
            u.passHash = await hashPassword(u.password);
            delete u.password;
            changed = true;
        }
        if (u.username === ADMIN_USERNAME && u.role !== 'admin') { u.role = 'admin'; changed = true; }
        if (typeof u.points !== 'number') { u.points = 0; changed = true; }
    }
    return changed;
}

// ===== لایه‌ی دیتابیس: کش در حافظه + صف نوشتن (جلوگیری از همزمانی) =====
let db = null;
let loading = null;

async function remoteGet() {
    const r = await fetch(DB_URL + '/latest', { headers: { 'X-Master-Key': API_KEY } });
    if (!r.ok) throw new Error('JSONBin GET ' + r.status);
    return (await r.json()).record;
}
async function remotePut(data) {
    const r = await fetch(DB_URL, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-Master-Key': API_KEY },
        body: JSON.stringify(data)
    });
    if (!r.ok) throw new Error('JSONBin PUT ' + r.status);
}
async function ensureLoaded() {
    if (db) return;
    if (!BIN_ID || !API_KEY) throw new HttpError(503, 'تنظیمات دیتابیس ناقص است');
    if (!loading) {
        loading = (async () => {
            let record = await remoteGet();
            let changed = false;
            if (!record || !Array.isArray(record.users) || record.users.length === 0) {
                record = seedDb(); changed = true;
            }
            if (await migrate(record)) changed = true;
            if (changed) await remotePut(record);
            db = record;
        })().finally(() => { loading = null; });
    }
    try { await loading; }
    catch (e) { console.error('Load error:', e.message); throw new HttpError(503, 'دیتابیس در دسترس نیست، کمی بعد دوباره تلاش کنید'); }
}
let queue = Promise.resolve();
function mutate(fn) {
    const run = queue.then(async () => {
        await ensureLoaded();
        const draft = structuredClone(db);
        const result = await fn(draft);
        try { await remotePut(draft); }
        catch (e) { console.error('Save error:', e.message); throw new HttpError(500, 'ذخیره‌سازی ناموفق بود'); }
        db = draft;
        return result;
    });
    queue = run.catch(() => {});
    return run;
}

// ===== توکن =====
const b64 = (s) => Buffer.from(s).toString('base64url');
function signToken(user) {
    const body = b64(JSON.stringify({ u: user.username, v: user.tv || 0, exp: Date.now() + TOKEN_TTL_MS }));
    const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
    return body + '.' + sig;
}
function readToken(token) {
    const [body, sig] = String(token || '').split('.');
    if (!body || !sig) return null;
    const good = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
    const a = Buffer.from(sig), b = Buffer.from(good);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    try {
        const p = JSON.parse(Buffer.from(body, 'base64url').toString());
        return p.exp > Date.now() ? p : null;
    } catch { return null; }
}
const isAdmin = (u) => u && u.role === 'admin';

const wrap = (fn) => (req, res) => fn(req, res).catch(err => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
    console.error(err);
    res.status(500).json({ error: 'خطای داخلی سرور' });
});

const auth = wrap2(async (req) => {
    await ensureLoaded();
    const h = req.headers.authorization || '';
    const p = readToken(h.startsWith('Bearer ') ? h.slice(7) : '');
    const user = p && db.users.find(u => u.username === p.u);
    if (!user || (user.tv || 0) !== p.v) throw new HttpError(401, 'نیاز به ورود مجدد');
    req.user = user;
});
function wrap2(fn) {
    return (req, res, next) => fn(req).then(() => next()).catch(err => {
        if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
        console.error(err); res.status(500).json({ error: 'خطای داخلی سرور' });
    });
}
const adminOnly = (req, res, next) => isAdmin(req.user) ? next() : res.status(403).json({ error: 'دسترسی ندارید' });

const publicUser = (u) => ({ username: u.username, displayName: u.displayName, points: u.points || 0 });
const teacherName = () => (db.users.find(isAdmin) || {}).displayName || 'استاد';
const str = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

// ===== محدودیت تلاش ورود =====
const attempts = new Map();
function checkLock(key) {
    const a = attempts.get(key);
    if (a && a.until > Date.now()) throw new HttpError(429, 'تلاش‌های زیاد؛ چند دقیقه بعد دوباره امتحان کنید');
}
function fail(key) {
    const a = attempts.get(key) || { count: 0, until: 0 };
    a.count += 1;
    if (a.count >= 5) { a.until = Date.now() + 10 * 60 * 1000; a.count = 0; }
    attempts.set(key, a);
}

// ===== مسیرهای عمومی =====
app.post('/api/login', wrap(async (req, res) => {
    await ensureLoaded();
    const username = str(req.body.username, 50).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password.slice(0, 200) : '';
    const key = req.ip + '|' + username;
    checkLock(key);
    const user = db.users.find(u => u.username === username);
    const ok = await verifyPassword(password, user ? user.passHash : await DUMMY_HASH_PROMISE);
    if (!user || !ok) { fail(key); throw new HttpError(401, 'نام کاربری یا رمز عبور اشتباه است'); }
    attempts.delete(key);
    res.json({ token: signToken(user) });
}));

// ===== مسیرهای کاربر واردشده =====
app.get('/api/me', auth, wrap(async (req, res) => {
    res.json({ ...publicUser(req.user), isAdmin: isAdmin(req.user), teacherName: teacherName() });
}));

app.get('/api/leaderboard', auth, wrap(async (req, res) => {
    res.json(db.users.filter(u => !isAdmin(u)).map(publicUser).sort((a, b) => b.points - a.points));
}));

app.get('/api/my-messages', auth, wrap(async (req, res) => {
    res.json(db.messages.filter(m => m.from === req.user.username).slice(-50).reverse());
}));

app.post('/api/messages', auth, wrap(async (req, res) => {
    const text = str(req.body.text, 500);
    if (!text) throw new HttpError(400, 'متن پیام خالی است');
    await mutate(async (d) => {
        const since = Date.now() - 10 * 60 * 1000;
        const recent = d.messages.filter(m => m.from === req.user.username && (m.createdAt || 0) > since).length;
        if (recent >= 5) throw new HttpError(429, 'تعداد پیام‌ها زیاد است؛ کمی بعد دوباره بفرستید');
        d.messages.push({
            id: crypto.randomUUID(), from: req.user.username, fromName: req.user.displayName,
            text, reply: null, createdAt: Date.now()
        });
    });
    res.json({ success: true });
}));

app.post('/api/change-password', auth, wrap(async (req, res) => {
    const oldPw = typeof req.body.oldPassword === 'string' ? req.body.oldPassword : '';
    const newPw = typeof req.body.newPassword === 'string' ? req.body.newPassword : '';
    if (newPw.length < 6 || newPw.length > 100) throw new HttpError(400, 'رمز جدید باید حداقل ۶ کاراکتر باشد');
    if (!(await verifyPassword(oldPw, req.user.passHash))) throw new HttpError(400, 'رمز فعلی اشتباه است');
    const hash = await hashPassword(newPw);
    let token;
    await mutate(async (d) => {
        const u = d.users.find(x => x.username === req.user.username);
        u.passHash = hash; u.tv = (u.tv || 0) + 1;
        token = signToken(u);
    });
    res.json({ token });
}));

// ===== مسیرهای معلم =====
const admin = [auth, adminOnly];

app.get('/api/admin/messages', admin, wrap(async (req, res) => {
    res.json([...db.messages].reverse());
}));
app.get('/api/admin/log', admin, wrap(async (req, res) => {
    res.json(db.log.slice(-50).reverse());
}));

app.post('/api/admin/messages/:id/reply', admin, wrap(async (req, res) => {
    const reply = str(req.body.reply, 500);
    if (!reply) throw new HttpError(400, 'متن پاسخ خالی است');
    await mutate(async (d) => {
        const m = d.messages.find(x => String(x.id) === req.params.id);
        if (!m) throw new HttpError(404, 'پیام پیدا نشد');
        m.reply = reply; m.repliedAt = Date.now();
    });
    res.json({ success: true });
}));

app.post('/api/admin/points', admin, wrap(async (req, res) => {
    const username = str(req.body.username, 50).toLowerCase();
    const amount = req.body.amount;
    const reason = str(req.body.reason, 200);
    if (!Number.isInteger(amount) || amount === 0 || Math.abs(amount) > 10000) throw new HttpError(400, 'مقدار امتیاز نامعتبر است');
    const total = await mutate(async (d) => {
        const u = d.users.find(x => x.username === username);
        if (!u || isAdmin(u)) throw new HttpError(404, 'دانش‌آموز پیدا نشد');
        u.points = (u.points || 0) + amount;
        d.log.push({ id: crypto.randomUUID(), at: Date.now(), by: req.user.username, to: u.username, toName: u.displayName, amount, reason, total: u.points });
        if (d.log.length > 2000) d.log.splice(0, d.log.length - 2000);
        return u.points;
    });
    res.json({ success: true, total });
}));

app.post('/api/admin/students', admin, wrap(async (req, res) => {
    const displayName = str(req.body.displayName, 60);
    const username = str(req.body.username, 30).toLowerCase();
    if (!displayName) throw new HttpError(400, 'نام نمایشی لازم است');
    if (!/^[a-z0-9_]{3,30}$/.test(username)) throw new HttpError(400, 'نام کاربری فقط حروف انگلیسی کوچک، عدد و _ (۳ تا ۳۰ کاراکتر)');
    const tempPassword = randomPassword();
    const passHash = await hashPassword(tempPassword);
    await mutate(async (d) => {
        if (d.users.some(u => u.username === username)) throw new HttpError(409, 'این نام کاربری قبلاً ثبت شده');
        d.users.push({ username, displayName, points: 0, passHash });
    });
    res.json({ success: true, tempPassword });
}));

app.post('/api/admin/students/:username/reset-password', admin, wrap(async (req, res) => {
    const tempPassword = randomPassword();
    const passHash = await hashPassword(tempPassword);
    await mutate(async (d) => {
        const u = d.users.find(x => x.username === req.params.username);
        if (!u || isAdmin(u)) throw new HttpError(404, 'دانش‌آموز پیدا نشد');
        u.passHash = passHash; u.tv = (u.tv || 0) + 1;
    });
    res.json({ success: true, tempPassword });
}));

app.delete('/api/admin/students/:username', admin, wrap(async (req, res) => {
    await mutate(async (d) => {
        const i = d.users.findIndex(x => x.username === req.params.username);
        if (i < 0 || isAdmin(d.users[i])) throw new HttpError(404, 'دانش‌آموز پیدا نشد');
        d.users.splice(i, 1);
    });
    res.json({ success: true });
}));

app.use('/api', (req, res) => res.status(404).json({ error: 'پیدا نشد' }));

app.listen(PORT, () => console.log(`Server running on ${PORT}`));
