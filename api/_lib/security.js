const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { put, list, del } = require('@vercel/blob');
const BUNDLED_PORTFOLIO = require('./portfolio.json');

const memoryStore = new Map();

/* ── 1. SERVER-SIDE SECRETS (CONFIGURED IN VERCEL ENVIRONMENT VARIABLES) ── */
const FALLBACK_SCRYPT_SALT = '87c02bd6dd95abe4398b4e208bffef50';
const FALLBACK_SCRYPT_HASH = '76247df7e8826d7c4e7f465c17a67261dd08db911c712ed0e509ab562b9be27d';

function getAdminSecret() {
  return process.env.ADMIN_SECRET || process.env.ADMIN_PASSWORD || FALLBACK_SCRYPT_HASH;
}

/* ── 2. TIMING-SAFE PASSWORD CHECK & HMAC-SHA256 SESSION TOKENS ── */
function verifyAdminPassword(candidate) {
  if (typeof candidate !== 'string' || !candidate) return false;
  if (process.env.ADMIN_PASSWORD) {
    const a = crypto.createHash('sha256').update(candidate).digest();
    const b = crypto.createHash('sha256').update(process.env.ADMIN_PASSWORD).digest();
    return crypto.timingSafeEqual(a, b);
  }
  const derived = crypto.scryptSync(candidate, FALLBACK_SCRYPT_SALT, 32);
  const expected = Buffer.from(FALLBACK_SCRYPT_HASH, 'hex');
  return crypto.timingSafeEqual(derived, expected);
}

function issueAdminToken() {
  const payload = {
    role: 'admin',
    iat: Date.now(),
    exp: Date.now() + 8 * 60 * 60 * 1000
  };
  const dataB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto
    .createHmac('sha256', getAdminSecret())
    .update(dataB64)
    .digest('base64url');
  return `${dataB64}.${sig}`;
}

function verifyAdminRequest(req) {
  const authHeader = req.headers.authorization || '';
  let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

  if (!token && req.headers.cookie) {
    const match = req.headers.cookie.match(/(?:^|;\s*)qh_admin_session=([^;]+)/);
    if (match) token = decodeURIComponent(match[1]);
  }
  if (!token || !token.includes('.')) return false;

  const [dataB64, sig] = token.split('.');
  const expectedSig = crypto
    .createHmac('sha256', getAdminSecret())
    .update(dataB64)
    .digest('base64url');

  const a = Buffer.from(sig || '');
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;

  try {
    const payload = JSON.parse(Buffer.from(dataB64, 'base64url').toString('utf8'));
    return payload.role === 'admin' && payload.exp > Date.now();
  } catch {
    return false;
  }
}

/* ── 3. SERVER-SIDE AES-256-GCM ENCRYPTION FOR BLOB & MESSAGES ── */
function deriveServerAesKey() {
  return crypto.scryptSync(getAdminSecret(), 'qh-portfolio-server-salt-v1', 32);
}

function encryptServerPayload(obj) {
  const key = deriveServerAesKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 'SERVER_AES_256_GCM_V1',
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: encrypted.toString('base64')
  };
}

function decryptServerPayload(envelope, fallback = []) {
  if (!envelope) return fallback;
  if (envelope.v !== 'SERVER_AES_256_GCM_V1') return envelope;
  try {
    const key = deriveServerAesKey();
    const iv = Buffer.from(envelope.iv, 'base64');
    const tag = Buffer.from(envelope.tag, 'base64');
    const ct = Buffer.from(envelope.ct, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(decrypted.toString('utf8'));
  } catch {
    return fallback;
  }
}

/* ── 4. PUBLIC DATA FILTER (STRIPS ALL HIDDEN ITEMS ON THE SERVER BEFORE F12 CAN SEE THEM) ── */
function toPublicPortfolio(raw) {
  const p = raw.profile || {};
  const emailVisible = p.emailVisible !== false;
  const igVisible = p.instagramVisible !== false;
  const photoVisible = p.photoVisible !== false;

  const sanitizeCard = item => ({
    id: item.id,
    title: item.title || '',
    desc: item.desc || '',
    date: item.date || '',
    url: item.url || '#',
    tags: Array.isArray(item.tags) ? item.tags : [],
    image: item.imageVisible !== false ? (item.image || '') : '',
    imageVisible: item.imageVisible !== false,
    visible: true
  });

  return {
    schemaVersion: 3,
    updatedAt: raw.updatedAt || 0,
    profile: {
      name: p.name || '',
      title: p.title || '',
      heroSubtitle: p.heroSubtitle || '',
      description1: p.description1 || '',
      description2: p.description2 || '',
      email: emailVisible ? (p.email || '') : '',
      emailVisible,
      instagram: igVisible ? (p.instagram || '') : '',
      instagramHandle: igVisible ? (p.instagramHandle || '') : '',
      instagramVisible: igVisible,
      photo: photoVisible ? (p.photo || '') : '',
      photoVisible
    },
    projects: (raw.projects || []).filter(x => x.visible !== false).map(sanitizeCard),
    events: (raw.events || []).filter(x => x.visible !== false).map(sanitizeCard),
    certifications: (raw.certifications || []).filter(x => x.visible !== false).map(sanitizeCard),
    technologies: (raw.technologies || []).filter(x => x.visible !== false)
  };
}

/* ── 5. VERCEL BLOB (AES-256-GCM ENCRYPTED, IMMUTABLE VERSIONED KEYS FOR ZERO CDN CACHE LAG) ── */
function toBlobPrefix(relPath) {
  return 'qh-vault-v4/' + path.basename(relPath) + '/';
}

async function readStorageFile(relPath, fallbackObj) {
  const prefix = toBlobPrefix(relPath);

  // 1. Primary Cloud Database: Vercel Blob (portafolio-blob)
  if (process.env.BLOB_READ_WRITE_TOKEN) {
    try {
      const { blobs } = await list({ prefix });
      if (blobs && blobs.length > 0) {
        blobs.sort((a, b) => b.pathname.localeCompare(a.pathname));
        const newest = blobs[0];
        if (newest && newest.url) {
          const res = await fetch(newest.url, { cache: 'no-store' });
          if (res.ok) {
            const envelope = await res.json();
            const decrypted = decryptServerPayload(envelope, fallbackObj);
            if (decrypted) {
              memoryStore.set(relPath, decrypted);
              return decrypted;
            }
          }
        }
      }
    } catch {}
  }

  // 2. In-memory / /tmp cache
  if (memoryStore.has(relPath)) {
    return JSON.parse(JSON.stringify(memoryStore.get(relPath)));
  }

  try {
    const tmpFile = path.join(os.tmpdir(), 'qh_' + relPath.replace(/[\\/]/g, '_'));
    if (fs.existsSync(tmpFile)) {
      return JSON.parse(fs.readFileSync(tmpFile, 'utf8'));
    }
  } catch {}

  try {
    const fullPath = path.join(process.cwd(), relPath);
    if (fs.existsSync(fullPath)) {
      return JSON.parse(fs.readFileSync(fullPath, 'utf8'));
    }
  } catch {}

  return fallbackObj !== undefined ? fallbackObj : BUNDLED_PORTFOLIO;
}

async function writeStorageFile(relPath, dataObj) {
  const cloned = JSON.parse(JSON.stringify(dataObj));
  memoryStore.set(relPath, cloned);

  const prefix = toBlobPrefix(relPath);

  // 1. Primary Cloud Database: Vercel Blob (AES-256-GCM Encrypted with unique URL per write)
  if (process.env.BLOB_READ_WRITE_TOKEN) {
    try {
      const encryptedEnvelope = encryptServerPayload(cloned);
      const ts = String(Date.now()).padStart(15, '0');
      const blobKey = `${prefix}${ts}.enc.json`;
      const created = await put(blobKey, JSON.stringify(encryptedEnvelope), {
        access: 'public',
        addRandomSuffix: true,
        contentType: 'application/json',
        cacheControlMaxAge: 0
      });

      // Clean up older versioned blobs so storage stays clean with only the latest snapshot
      try {
        const { blobs } = await list({ prefix });
        const oldUrls = (blobs || []).filter(b => b.url !== created.url).map(b => b.url);
        if (oldUrls.length > 0) {
          await del(oldUrls);
        }
      } catch {}

      return { persisted: 'vercel-blob-encrypted', blobUrl: created.url };
    } catch (blobErr) {
      console.warn('Vercel Blob write error, falling back to disk cache:', blobErr);
    }
  }

  // 2. Local filesystem / /tmp fallback
  const contentStr = JSON.stringify(cloned, null, 2);
  try {
    const fullPath = path.join(process.cwd(), relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, contentStr, 'utf8');
    return { persisted: 'local-fs' };
  } catch {
    const tmpFile = path.join(os.tmpdir(), 'qh_' + relPath.replace(/[\\/]/g, '_'));
    fs.writeFileSync(tmpFile, contentStr, 'utf8');
    return { persisted: 'vercel-tmp' };
  }
}

function isAiOrScraperBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const aiSignatures = [
    'gptbot', 'chatgpt', 'ccbot', 'claude', 'anthropic', 'google-extended',
    'bytespider', 'diffbot', 'facebookbot', 'meta-externalagent', 'perplexity',
    'cohere', 'applebot-extended', 'amazonbot', 'scrapy', 'python-requests',
    'aiohttp', 'curl', 'wget', 'urllib', 'headlesschrome', 'puppeteer', 'selenium'
  ];
  return aiSignatures.some(sig => ua.includes(sig));
}

module.exports = {
  BUNDLED_PORTFOLIO,
  verifyAdminPassword,
  issueAdminToken,
  verifyAdminRequest,
  encryptServerPayload,
  decryptServerPayload,
  toPublicPortfolio,
  readStorageFile,
  writeStorageFile,
  isAiOrScraperBot
};
