const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { put, list, del } = require('@vercel/blob');
const BUNDLED_PORTFOLIO = require('./portfolio.json');

/* ─────────────────────────────────────────────────────────────
   0. ERRORES TIPADOS
   Las funciones de almacenamiento LANZAN errores en lugar de devolver
   datos por defecto en silencio. Antes, un fallo temporal de Vercel Blob
   devolvía el portfolio.json original y el admin lo sobrescribía al
   guardar, borrando imágenes y textos.
   ───────────────────────────────────────────────────────────── */
class StorageError extends Error {
  constructor(message, cause) {
    super(message);
    this.name = 'StorageError';
    this.cause = cause;
  }
}

class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

const hasBlob = () => Boolean(process.env.BLOB_READ_WRITE_TOKEN);

/* ── 1. SECRETOS DEL SERVIDOR (VARIABLES DE ENTORNO EN VERCEL) ──
   Ya NO existe un secreto por defecto para firmar sesiones: el valor de
   respaldo estaba publicado en el repositorio y permitía falsificar tokens.
   Se conserva solo para DESCIFRAR datos antiguos guardados con él. */
const LEGACY_SCRYPT_SALT = '87c02bd6dd95abe4398b4e208bffef50';
const LEGACY_SCRYPT_HASH = '76247df7e8826d7c4e7f465c17a67261dd08db911c712ed0e509ab562b9be27d';

function getSigningSecret() {
  return process.env.ADMIN_SECRET || process.env.ADMIN_PASSWORD || null;
}

function requireSigningSecret() {
  const s = getSigningSecret();
  if (!s) {
    throw new ConfigError('Falta configurar ADMIN_SECRET (o ADMIN_PASSWORD) en las variables de entorno de Vercel.');
  }
  return s;
}

/* ── 2. VERIFICACIÓN DE CONTRASEÑA (TIEMPO CONSTANTE) Y TOKENS HMAC ── */
function verifyAdminPassword(candidate) {
  if (typeof candidate !== 'string' || !candidate) return false;
  if (process.env.ADMIN_PASSWORD) {
    const a = crypto.createHash('sha256').update(candidate).digest();
    const b = crypto.createHash('sha256').update(process.env.ADMIN_PASSWORD).digest();
    return crypto.timingSafeEqual(a, b);
  }
  const derived = crypto.scryptSync(candidate, LEGACY_SCRYPT_SALT, 32);
  const expected = Buffer.from(LEGACY_SCRYPT_HASH, 'hex');
  return crypto.timingSafeEqual(derived, expected);
}

function issueAdminToken() {
  const secret = requireSigningSecret();
  const payload = {
    role: 'admin',
    iat: Date.now(),
    exp: Date.now() + 8 * 60 * 60 * 1000
  };
  const dataB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(dataB64).digest('base64url');
  return `${dataB64}.${sig}`;
}

function verifyAdminRequest(req) {
  const secret = getSigningSecret();
  if (!secret) return false;

  const authHeader = req.headers.authorization || '';
  let token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

  if (!token && req.headers.cookie) {
    const match = req.headers.cookie.match(/(?:^|;\s*)qh_admin_session=([^;]+)/);
    if (match) token = decodeURIComponent(match[1]);
  }
  if (!token || !token.includes('.')) return false;

  const [dataB64, sig] = token.split('.');
  const expectedSig = crypto.createHmac('sha256', secret).update(dataB64).digest('base64url');

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

/* ── 3. CIFRADO AES-256-GCM DE LOS DATOS GUARDADOS ──
   Se cifra con ADMIN_SECRET || ADMIN_PASSWORD (igual que antes, para ser
   compatible) y al descifrar se prueban todas las llaves posibles. Así, si
   cambias o agregas una variable, los datos viejos siguen siendo legibles. */
const keyCache = new Map();
function deriveKey(secret) {
  if (!keyCache.has(secret)) {
    keyCache.set(secret, crypto.scryptSync(secret, 'qh-portfolio-server-salt-v1', 32));
  }
  return keyCache.get(secret);
}

function candidateSecrets() {
  // PREVIOUS_ADMIN_SECRETS (separadas por coma): valores ANTERIORES de ADMIN_SECRET o
  // ADMIN_PASSWORD. Permiten cambiar la contraseña sin perder acceso a los datos ya cifrados.
  const previous = String(process.env.PREVIOUS_ADMIN_SECRETS || '').split(',').map(x => x.trim());
  return [...new Set([process.env.ADMIN_SECRET, process.env.ADMIN_PASSWORD, ...previous, LEGACY_SCRYPT_HASH].filter(Boolean))];
}

function encryptServerPayload(obj) {
  const key = deriveKey(requireSigningSecret());
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(obj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    v: 'SERVER_AES_256_GCM_V1',
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: encrypted.toString('base64')
  };
}

/** Lanza StorageError si no se puede descifrar (nunca devuelve datos por defecto). */
function decryptServerPayload(envelope) {
  if (!envelope || typeof envelope !== 'object') throw new StorageError('Contenido vacío o inválido');
  if (envelope.v !== 'SERVER_AES_256_GCM_V1') return envelope; // dato sin cifrar (legado)
  const iv = Buffer.from(envelope.iv, 'base64');
  const tag = Buffer.from(envelope.tag, 'base64');
  const ct = Buffer.from(envelope.ct, 'base64');
  for (const secret of candidateSecrets()) {
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', deriveKey(secret), iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
      return JSON.parse(decrypted.toString('utf8'));
    } catch {}
  }
  throw new StorageError('No se pudo descifrar: ¿cambió ADMIN_SECRET / ADMIN_PASSWORD en Vercel?');
}

/* ── 4. FILTRO PÚBLICO (OCULTA EN EL SERVIDOR LO QUE NO ES VISIBLE) ── */
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
    schemaVersion: Number(raw.schemaVersion) || 3,
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
      photoVisible,
      location: typeof p.location === 'string' ? p.location.slice(0, 80) : '',
      whatsapp: typeof p.whatsapp === 'string' ? p.whatsapp.replace(/\D/g, '').slice(0, 15) : ''
    },
    projects: (raw.projects || []).filter(x => x.visible !== false).map(sanitizeCard),
    events: (raw.events || []).filter(x => x.visible !== false).map(sanitizeCard),
    certifications: (raw.certifications || []).filter(x => x.visible !== false).map(sanitizeCard),
    technologies: (raw.technologies || []).filter(x => x.visible !== false)
  };
}

/* ── 5. ALMACENAMIENTO VERSIONADO EN VERCEL BLOB ──
   • Cada guardado crea un archivo nuevo e inmutable (nombre = timestamp).
   • Se conservan las últimas MAX_VERSIONS versiones (historial restaurable),
     en lugar de borrar todo lo anterior (lo que causaba carreras y pérdidas).
   • Si algo falla se LANZA un error: nada de /tmp ni datos por defecto. */
const MAX_VERSIONS = 15;
const PRUNE_SLACK = 5; // las versiones viejas se borran por lotes, no en cada guardado
const memoryStore = new Map(); // relPath -> { data, updatedAt } (solo como respaldo de consistencia)

/* Caché de contenido INMUTABLE: cada versión y cada mensaje tiene un nombre único que
   nunca se reescribe, así que lo ya descargado y descifrado no se vuelve a pedir.
   Solo se sigue consultando el listado (para enterarse de lo nuevo). */
const CONTENT_CACHE_MAX = 400;
const contentCache = new Map(); // pathname -> datos descifrados
const lastListing = new Map(); // prefix -> { at, blobs } (para limpiar sin volver a listar)
// El listado de Blob puede tardar en reflejar un borrado: se recuerda lo borrado aquí.
const deletedPaths = new Set();
function forget(blobs) {
  for (const b of blobs) { deletedPaths.add(b.pathname); contentCache.delete(b.pathname); }
  if (deletedPaths.size > 2000) deletedPaths.clear();
}

function cacheContent(pathname, data) {
  if (contentCache.has(pathname)) contentCache.delete(pathname);
  else if (contentCache.size >= CONTENT_CACHE_MAX) contentCache.delete(contentCache.keys().next().value);
  contentCache.set(pathname, clone(data));
}

async function readBlobData(blob) {
  if (contentCache.has(blob.pathname)) return clone(contentCache.get(blob.pathname));
  const data = decryptServerPayload(await fetchBlobJson(blob.url));
  cacheContent(blob.pathname, data);
  return clone(data);
}

function toBlobPrefix(relPath) {
  return 'qh-vault-v4/' + path.basename(relPath) + '/';
}

async function withRetry(fn, attempts = 3) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      await new Promise(r => setTimeout(r, 250 * (i + 1)));
    }
  }
  throw lastErr;
}

async function listAll(prefix) {
  const out = [];
  let cursor;
  do {
    const res = await withRetry(() => list({ prefix, cursor, limit: 1000 }));
    out.push(...(res.blobs || []));
    cursor = res.hasMore ? res.cursor : undefined;
  } while (cursor);
  // Los nombres empiezan con un timestamp de 15 dígitos -> orden lexicográfico = cronológico.
  out.sort((a, b) => b.pathname.localeCompare(a.pathname));
  lastListing.set(prefix, { at: Date.now(), blobs: out });
  return out;
}

async function fetchBlobJson(url) {
  return withRetry(async () => {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new StorageError(`Blob respondió HTTP ${res.status}`);
    return res.json();
  });
}

function versionKey(prefix, ts = Date.now()) {
  return `${prefix}${String(ts).padStart(15, '0')}-${crypto.randomBytes(4).toString('hex')}.enc.json`;
}

function localPath(relPath) {
  return path.join(process.cwd(), relPath);
}

/**
 * Lee el dato más reciente.
 * - Si NO existe ninguna versión todavía (primer uso) devuelve `fallbackObj`.
 * - Si existe pero no se puede leer/descifrar, LANZA StorageError.
 */
async function readStorageFile(relPath, fallbackObj) {
  if (hasBlob()) {
    let blobs;
    try {
      blobs = await listAll(toBlobPrefix(relPath));
    } catch (err) {
      throw new StorageError('No se pudo consultar Vercel Blob', err);
    }

    const mem = memoryStore.get(relPath);
    if (!blobs.length) {
      return mem ? clone(mem.data) : clone(fallbackObj);
    }

    let data;
    try {
      data = await readBlobData(blobs[0]);
    } catch (err) {
      throw err instanceof StorageError ? err : new StorageError('No se pudo leer la última versión', err);
    }

    // `list()` puede tardar unos segundos en reflejar una escritura reciente:
    // si esta misma instancia escribió algo más nuevo, se prefiere eso.
    if (mem && Number(mem.updatedAt) > Number(data && data.updatedAt)) return clone(mem.data);
    return data;
  }

  // Desarrollo local (sin Vercel Blob): archivo en disco.
  const file = localPath(relPath);
  if (!fs.existsSync(file)) return clone(fallbackObj);
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    throw new StorageError('Archivo local corrupto: ' + relPath, err);
  }
}

/** Guarda una nueva versión. LANZA StorageError si no se pudo persistir. */
async function writeStorageFile(relPath, dataObj) {
  const cloned = clone(dataObj);

  if (hasBlob()) {
    const prefix = toBlobPrefix(relPath);
    let created;
    try {
      created = await withRetry(() =>
        put(versionKey(prefix), JSON.stringify(encryptServerPayload(cloned)), {
          access: 'public',
          addRandomSuffix: false,
          contentType: 'application/json',
          cacheControlMaxAge: 60 // mínimo permitido; cada versión tiene URL única
        })
      );
    } catch (err) {
      if (err instanceof ConfigError) throw err;
      throw new StorageError('No se pudo guardar en Vercel Blob', err);
    }
    memoryStore.set(relPath, { data: cloned, updatedAt: Number(cloned && cloned.updatedAt) || 0 });
    cacheContent(created.pathname, cloned);

    // Limpieza por lotes: se reutiliza el listado reciente (no se vuelve a listar) y solo se
    // borra cuando sobran más de PRUNE_SLACK versiones. Únicamente se borran versiones
    // más viejas que las MAX_VERSIONS más recientes conocidas (los errores no son críticos).
    try {
      const known = lastListing.get(prefix);
      const base = known && Date.now() - known.at < 60 * 1000 ? known.blobs : await listAll(prefix);
      const merged = [{ pathname: created.pathname, url: created.url }, ...base.filter(b => b.pathname !== created.pathname)]
        .sort((a, b) => b.pathname.localeCompare(a.pathname));
      if (merged.length > MAX_VERSIONS + PRUNE_SLACK) {
        await del(merged.slice(MAX_VERSIONS).map(b => b.url));
        lastListing.set(prefix, { at: Date.now(), blobs: merged.slice(0, MAX_VERSIONS) });
      } else {
        lastListing.set(prefix, { at: Date.now(), blobs: merged });
      }
    } catch {}

    return { persisted: 'vercel-blob', blobUrl: created.url };
  }

  try {
    const file = localPath(relPath);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(cloned, null, 2), 'utf8');
    memoryStore.set(relPath, { data: cloned, updatedAt: Number(cloned && cloned.updatedAt) || 0 });
    return { persisted: 'local-fs' };
  } catch (err) {
    throw new StorageError(
      'No hay almacenamiento persistente: configura BLOB_READ_WRITE_TOKEN en Vercel.',
      err
    );
  }
}

/** Historial de versiones (más reciente primero). */
async function listStorageVersions(relPath) {
  if (!hasBlob()) return [];
  const blobs = (await listAll(toBlobPrefix(relPath))).slice(0, MAX_VERSIONS);
  return blobs.map(b => ({
    id: b.pathname,
    ts: Number((path.basename(b.pathname).match(/^(\d{10,15})/) || [])[1]) || new Date(b.uploadedAt).getTime(),
    uploadedAt: b.uploadedAt,
    size: b.size
  }));
}

async function readStorageVersion(relPath, versionId) {
  if (!hasBlob()) throw new StorageError('El historial requiere Vercel Blob');
  const prefix = toBlobPrefix(relPath);
  if (typeof versionId !== 'string' || !versionId.startsWith(prefix)) {
    throw new StorageError('Versión inválida');
  }
  const blob = (await listAll(prefix)).find(b => b.pathname === versionId);
  if (!blob) throw new StorageError('La versión ya no existe');
  return readBlobData(blob);
}

/* ── 6. IMÁGENES COMO ARCHIVOS SEPARADOS ──
   Antes las imágenes iban en base64 dentro del JSON: el JSON crecía a
   cientos de KB / varios MB, superaba el límite de 64 KB de `keepalive`
   (los guardados fallaban en silencio) y el de 4.5 MB de Vercel. */
const MAX_IMAGE_BYTES = 3 * 1024 * 1024;
const IMAGE_TYPES = {
  'image/webp': { ext: 'webp', magic: b => b.slice(0, 4).toString() === 'RIFF' && b.slice(8, 12).toString() === 'WEBP' },
  'image/jpeg': { ext: 'jpg', magic: b => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff },
  'image/png': { ext: 'png', magic: b => b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) }
};

function isDataImage(v) {
  return typeof v === 'string' && v.startsWith('data:image/');
}

async function uploadImageDataUrl(dataUrl) {
  const m = /^data:(image\/(?:webp|jpeg|png));base64,([A-Za-z0-9+/=\s]+)$/.exec(String(dataUrl || ''));
  if (!m) throw new StorageError('Formato de imagen no permitido (usa WebP, JPEG o PNG)');
  const type = IMAGE_TYPES[m[1]];
  const buf = Buffer.from(m[2], 'base64');
  if (!buf.length || buf.length > MAX_IMAGE_BYTES) throw new StorageError('La imagen supera 3 MB');
  if (!type.magic(buf)) throw new StorageError('El contenido no coincide con el tipo de imagen');

  if (!hasBlob()) return dataUrl; // desarrollo local: se queda en línea

  const key = `qh-media-v1/${Date.now()}-${crypto.randomBytes(8).toString('hex')}.${type.ext}`;
  try {
    const created = await withRetry(() =>
      put(key, buf, {
        access: 'public',
        addRandomSuffix: false,
        contentType: m[1],
        cacheControlMaxAge: 31536000
      })
    );
    return created.url;
  } catch (err) {
    throw new StorageError('No se pudo subir la imagen', err);
  }
}

/** Sustituye cualquier imagen base64 del portafolio por una URL de Blob. */
async function externalizeImages(portfolio) {
  let count = 0;
  if (portfolio.profile && isDataImage(portfolio.profile.photo)) {
    portfolio.profile.photo = await uploadImageDataUrl(portfolio.profile.photo);
    count++;
  }
  for (const col of ['projects', 'events', 'certifications']) {
    for (const item of portfolio[col] || []) {
      if (isDataImage(item.image)) {
        item.image = await uploadImageDataUrl(item.image);
        count++;
      }
    }
  }
  return count;
}

/* ── 7. MENSAJES: UN ARCHIVO POR MENSAJE ──
   Antes todos los mensajes estaban en un solo JSON que se leía, modificaba
   y reescribía: dos operaciones simultáneas podían borrarse entre sí. */
const INBOX_PREFIX = 'qh-inbox-v1/';
const LEGACY_MESSAGES = 'api/_lib/messages.json';
const MAX_MESSAGES = 200;

async function addMessage(msg) {
  if (!hasBlob()) {
    const current = await readStorageFile(LEGACY_MESSAGES, []);
    const listArr = Array.isArray(current) ? current : [];
    listArr.unshift(msg);
    await writeStorageFile(LEGACY_MESSAGES, listArr.slice(0, MAX_MESSAGES));
    return;
  }
  const key = `${INBOX_PREFIX}${String(msg.id).padStart(15, '0')}-${crypto.randomBytes(4).toString('hex')}.enc.json`;
  try {
    await withRetry(() =>
      put(key, JSON.stringify(encryptServerPayload(msg)), {
        access: 'public',
        addRandomSuffix: false,
        contentType: 'application/json',
        cacheControlMaxAge: 60
      })
    );
  } catch (err) {
    throw new StorageError('No se pudo guardar el mensaje', err);
  }
  try {
    const blobs = await listAll(INBOX_PREFIX);
    const old = blobs.slice(MAX_MESSAGES).map(b => b.url);
    if (old.length) await del(old);
  } catch {}
}

function idFromInboxPath(p) {
  return Number((path.basename(p).match(/^(\d+)-/) || [])[1]) || 0;
}

async function listMessages() {
  // Bandeja antigua y nueva se consultan en paralelo
  const [legacy, allBlobs] = await Promise.all([
    readStorageFile(LEGACY_MESSAGES, []),
    hasBlob() ? listAll(INBOX_PREFIX) : Promise.resolve([])
  ]);
  const legacyList = Array.isArray(legacy) ? legacy : [];
  if (!hasBlob()) return legacyList;

  const blobs = allBlobs.filter(b => !deletedPaths.has(b.pathname)).slice(0, MAX_MESSAGES);
  const msgs = await Promise.all(
    blobs.map(async b => {
      try {
        return await readBlobData(b);
      } catch {
        return { id: idFromInboxPath(b.pathname), name: '[No se pudo leer]', email: '', message: 'Este mensaje no se pudo descifrar.', date: '' };
      }
    })
  );
  return [...msgs, ...legacyList].sort((a, b) => Number(b.id) - Number(a.id));
}

async function deleteMessage(id) {
  const msgId = Number(id);
  const [blobs, legacy] = await Promise.all([
    hasBlob() ? listAll(INBOX_PREFIX) : Promise.resolve([]),
    readStorageFile(LEGACY_MESSAGES, [])
  ]);
  const doomed = blobs.filter(b => idFromInboxPath(b.pathname) === msgId);
  if (doomed.length) { await del(doomed.map(b => b.url)); forget(doomed); }
  if (Array.isArray(legacy) && legacy.some(m => Number(m.id) === msgId)) {
    await writeStorageFile(LEGACY_MESSAGES, legacy.filter(m => Number(m.id) !== msgId));
  }
}

async function clearMessages() {
  if (hasBlob()) {
    const blobs = await listAll(INBOX_PREFIX);
    if (blobs.length) { await del(blobs.map(b => b.url)); forget(blobs); }
  }
  const legacy = await readStorageFile(LEGACY_MESSAGES, []);
  if (Array.isArray(legacy) && legacy.length) await writeStorageFile(LEGACY_MESSAGES, []);
}

/* ── 8. VALIDACIÓN DE ORIGEN, BOTS Y UTILIDADES ── */
function isAiOrScraperBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const aiSignatures = [
    'gptbot', 'chatgpt', 'ccbot', 'claude', 'anthropic', 'google-extended',
    'bytespider', 'diffbot', 'facebookbot', 'meta-externalagent', 'perplexity',
    'cohere', 'applebot-extended', 'amazonbot', 'scrapy', 'python-requests',
    'aiohttp', 'curl', 'wget', 'urllib', 'headlesschrome', 'puppeteer', 'selenium',
    'timpibot', 'youbot', 'webzio', 'dataminr', 'brightedge', 'postman'
  ];
  return aiSignatures.some(sig => ua.includes(sig));
}

/**
 * Solo se acepta el mismo host que atiende la petición, los hosts listados
 * en ALLOWED_ORIGINS (separados por coma) y localhost exacto.
 * Antes bastaba con que el host CONTUVIERA "vercel.app" (cualquier sitio de Vercel).
 */
function isAllowedOrigin(req) {
  const origin = req.headers.origin || req.headers.referer;
  if (!origin) return true;
  try {
    const url = new URL(origin);
    const host = url.host.toLowerCase();
    const serverHost = String(req.headers.host || '').toLowerCase();
    if (serverHost && host === serverHost) return true;
    const extra = String(process.env.ALLOWED_ORIGINS || '')
      .split(',')
      .map(s => s.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, ''))
      .filter(Boolean);
    if (extra.includes(host)) return true;
    return url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  } catch {
    return false;
  }
}

function sanitizeString(str, maxLength = 1000) {
  if (typeof str !== 'string') return '';
  return str.slice(0, maxLength).replace(/[<>]/g, '').trim();
}

function clone(v) {
  return v === undefined ? v : JSON.parse(JSON.stringify(v));
}

function parseBody(req) {
  if (typeof req.body === 'string') {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }
  return req.body || {};
}

function clientIp(req) {
  return String(req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || 'unknown')
    .split(',')[0]
    .trim();
}

/* ── 9. LÍMITE DE INTENTOS DE LOGIN (persistente y compartido entre instancias) ──
   Cada intento fallido se anota en Vercel Blob (con la IP convertida en un hash, nunca en
   claro). Así el bloqueo vale para TODAS las instancias de Vercel, no solo para una. */
const GUARD_PREFIX = 'qh-guard-v1/';
const GUARD_WINDOW_MS = 15 * 60 * 1000;
const GUARD_MAX_FAILS = 5;     // por IP dentro de la ventana -> bloqueo
const GUARD_GLOBAL_SLOW = 20;  // fallos de todas las IPs en la ventana -> respuestas más lentas
const guardMemory = new Map(); // respaldo si Blob no está disponible

function ipKey(ip) {
  return crypto.createHash('sha256').update('qh-guard:' + String(ip)).digest('hex').slice(0, 24);
}

function guardEntries(blobs, now) {
  return blobs
    .map(b => {
      const m = path.basename(b.pathname).match(/^(\d{15})-([a-f0-9]{24})-/);
      return m ? { ts: Number(m[1]), ip: m[2], url: b.url } : null;
    })
    .filter(Boolean)
    .filter(e => now - e.ts < GUARD_WINDOW_MS);
}

async function loginGuardStatus(ip) {
  const now = Date.now();
  const key = ipKey(ip);
  let entries;
  if (hasBlob()) {
    entries = guardEntries(await listAll(GUARD_PREFIX), now);
  } else {
    entries = (guardMemory.get('all') || []).filter(e => now - e.ts < GUARD_WINDOW_MS);
  }
  const mine = entries.filter(e => e.ip === key).sort((a, b) => b.ts - a.ts);
  const blocked = mine.length >= GUARD_MAX_FAILS;
  const retryAfterSec = blocked
    ? Math.max(1, Math.ceil((mine[GUARD_MAX_FAILS - 1].ts + GUARD_WINDOW_MS - now) / 1000))
    : 0;
  return { blocked, retryAfterSec, ipFails: mine.length, globalFails: entries.length };
}

async function loginGuardFail(ip) {
  const now = Date.now();
  const entry = { ts: now, ip: ipKey(ip) };
  if (!hasBlob()) {
    const arr = (guardMemory.get('all') || []).filter(e => now - e.ts < GUARD_WINDOW_MS);
    arr.push(entry);
    guardMemory.set('all', arr);
    return;
  }
  await put(`${GUARD_PREFIX}${String(now).padStart(15, '0')}-${entry.ip}-${crypto.randomBytes(4).toString('hex')}.json`, '{}', {
    access: 'public',
    addRandomSuffix: false,
    contentType: 'application/json',
    cacheControlMaxAge: 60
  });
  // Limpieza de anotaciones vencidas (no crítica)
  try {
    const old = (await listAll(GUARD_PREFIX))
      .filter(b => { const m = path.basename(b.pathname).match(/^(\d{15})-/); return m && now - Number(m[1]) > GUARD_WINDOW_MS; })
      .map(b => b.url);
    if (old.length) await del(old);
  } catch {}
}

async function loginGuardReset(ip) {
  const key = ipKey(ip);
  if (!hasBlob()) {
    guardMemory.set('all', (guardMemory.get('all') || []).filter(e => e.ip !== key));
    return;
  }
  const mine = (await listAll(GUARD_PREFIX)).filter(b => b.pathname.includes('-' + key + '-'));
  if (mine.length) await del(mine.map(b => b.url));
}

module.exports = {
  loginGuardStatus,
  loginGuardFail,
  loginGuardReset,
  GUARD_GLOBAL_SLOW,
  BUNDLED_PORTFOLIO,
  StorageError,
  ConfigError,
  verifyAdminPassword,
  issueAdminToken,
  verifyAdminRequest,
  encryptServerPayload,
  decryptServerPayload,
  toPublicPortfolio,
  readStorageFile,
  writeStorageFile,
  listStorageVersions,
  readStorageVersion,
  uploadImageDataUrl,
  externalizeImages,
  addMessage,
  listMessages,
  deleteMessage,
  clearMessages,
  isAiOrScraperBot,
  isAllowedOrigin,
  sanitizeString,
  parseBody,
  clientIp
};
