import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { openDatabase } from './db.mjs';
import { cookieValue, isUsername, isPasskeyName, normalizeName } from './security.mjs';
import {
  createSession, issueChallenge, consumeChallenge, cancelChallenge, lookupSession,
  revokeSession, seedFictionalItems, deleteCredentialKeepingOne
} from './services.mjs';

const baseDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const publicDir = path.join(baseDir, 'public');
const originalHtml = path.join(baseDir, 'index.html');
const SESSION_COOKIE = 'passkey_session';

function httpError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}
function requireAccount(req) {
  if (!req.account) throw httpError(401, '패스키 로그인이 필요합니다.');
  return req.account;
}
function cookieSettings(secure) {
  return { httpOnly: true, sameSite: 'lax', secure, path: '/', maxAge: 12 * 60 * 60 * 1000 };
}
function verifyEnvironment(config) {
  const origin = (config.ORIGIN || 'http://localhost:3000').replace(/\/$/, '');
  const parsed = new URL(origin);
  if (!['https:', 'http:'].includes(parsed.protocol)) throw new Error('ORIGIN 설정 오류');
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
    throw new Error('WebAuthn은 HTTPS 또는 localhost에서만 허용됩니다.');
  }
  const rpID = config.RP_ID || parsed.hostname;
  if (rpID !== parsed.hostname && !parsed.hostname.endsWith('.' + rpID)) {
    throw new Error('RP_ID는 ORIGIN 도메인 또는 그 상위 도메인이어야 합니다.');
  }
  if (config.VERCEL && !config.DATABASE_URL) throw new Error('Vercel 환경에서는 영구 DATABASE_URL이 필요합니다.');
  return { origin, rpID, secure: parsed.protocol === 'https:' };
}

export async function createApp({ config = process.env, db = null, webauthn = null } = {}) {
  const { origin, rpID, secure } = verifyEnvironment(config);
  const store = db || await openDatabase(config);
  const wa = webauthn || {
    generateRegistrationOptions, verifyRegistrationResponse,
    generateAuthenticationOptions, verifyAuthenticationResponse,
  };
  const app = express();
  // 원본 1번 과제 HTML의 인라인 CSS/JS는 변경하지 않고, 정확한 해시만 CSP에 허용.
  const html = readFileSync(originalHtml, 'utf8');
  const hashed = tag => [...html.matchAll(new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'gi'))]
    .map(match => `'sha256-${createHash('sha256').update(match[1], 'utf8').digest('base64')}'`);
  const scriptHashes = hashed('script');
  const styleHashes = hashed('style');
  app.disable('x-powered-by');
  app.set('trust proxy', false);
  app.use((_req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', `default-src 'self'; script-src 'self' ${scriptHashes.join(' ')}; style-src 'self' ${styleHashes.join(' ')}; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`);
    next();
  });
  app.use(express.json({ limit: '70kb', strict: true }));
  app.use('/api', async (req, _res, next) => {
    try {
      // 교차 사이트 상태변경 요청 차단. 쿠키에 SameSite를 병행 적용.
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && req.headers.origin !== origin) {
        throw httpError(403, '요청 출처가 허용되지 않았습니다.');
      }
      req.sessionToken = cookieValue(req, SESSION_COOKIE);
      req.account = await lookupSession(store, req.sessionToken);
      next();
    } catch (err) { next(err); }
  });
  app.get('/api/health', (_req, res) => res.json({ ok: true, application: 'task8-passkey' }));
  app.get('/api/me', (req, res) => {
    res.json({ loggedIn: !!req.account, account: req.account || null });
  });

  // 첫 번째 패스키로 새 계정 생성 또는 로그인 상태에서 추가 패스키 등록
  app.post('/api/registration/options', async (req, res) => {
    const mode = req.body?.mode;
    const name = normalizeName(req.body?.passkeyName);
    if (!isPasskeyName(name)) throw httpError(400, '패스키 이름은 1~48자여야 합니다.');
    let userId, username, userHandle, existing = [];
    if (mode === 'create') {
      if (req.account) throw httpError(409, '새 계정을 만들기 전 로그아웃하세요.');
      username = normalizeName(req.body?.username).toLowerCase();
      if (!isUsername(username)) throw httpError(400, '계정 이름은 영문 소문자·숫자·-를 사용해 3~24자로 입력하세요.');
      if (await store.one('SELECT id FROM accounts WHERE username=?', [username])) {
        throw httpError(409, '이미 사용 중인 계정 이름입니다.');
      }
      userId = randomUUID();
      userHandle = randomBytes(32).toString('base64url');
    } else if (mode === 'add') {
      const account = requireAccount(req);
      const user = await store.one('SELECT * FROM accounts WHERE id=?', [account.id]);
      if (!user) throw httpError(401, '유효하지 않은 세션입니다.');
      ({ id: userId, username, user_handle: userHandle } = user);
      existing = await store.all('SELECT id, transports FROM passkeys WHERE user_id=?', [userId]);
    } else {
      throw httpError(400, '등록 방식은 create 또는 add여야 합니다.');
    }
    const options = await wa.generateRegistrationOptions({
      rpName: '과제 8 - 나의 학습 아카이브', rpID,
      userName: username, userDisplayName: username,
      userID: new Uint8Array(Buffer.from(userHandle, 'base64url')),
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      excludeCredentials: existing.map(k => ({ id: k.id, transports: JSON.parse(k.transports) })),
      timeout: 60_000,
    });
    const ticket = await issueChallenge(store, {
      kind: mode === 'create' ? 'registration_create' : 'registration_add',
      challenge: options.challenge, userId, username, userHandle, passkeyName: name,
    });
    res.json({ ticket, options });
  });

  // 인증기 대화상자를 취소한 경우 대기 챌린지 즉시 정리 (계정·패스키 생성 없음).
  app.post('/api/ceremony/cancel', async (req, res) => {
    await cancelChallenge(store, req.body?.ticket);
    res.json({ cancelled: true });
  });

  app.post('/api/registration/verify', async (req, res) => {
    const { ticket, mode, credential } = req.body || {};
    const kind = mode === 'create' ? 'registration_create' : mode === 'add' ? 'registration_add' : '';
    if (!kind) throw httpError(400, '등록 방식이 올바르지 않습니다.');
    const pending = await consumeChallenge(store, ticket, kind);
    if (!pending) throw httpError(409, '챌린지가 이미 사용되었거나 만료되었습니다. 다시 요청하세요.');
    if (kind === 'registration_add' && (!req.account || req.account.id !== pending.user_id)) {
      throw httpError(403, '현재 로그인된 계정에만 패스키를 추가할 수 있습니다.');
    }
    if (!credential || typeof credential !== 'object') throw httpError(400, '패스키 응답이 없습니다.');
    let result;
    try {
      result = await wa.verifyRegistrationResponse({
        response: credential, expectedChallenge: pending.challenge,
        expectedOrigin: origin, expectedRPID: rpID,
        requireUserVerification: true,
      });
    } catch {
      throw httpError(400, '패스키 등록의 서명·출처·챌린지 검증에 실패했습니다.');
    }
    if (!result.verified || !result.registrationInfo?.credential) {
      throw httpError(400, '패스키 등록 검증에 실패했습니다.');
    }
    const { credential: saved, credentialDeviceType, credentialBackedUp } = result.registrationInfo;
    try {
      await store.transaction(async tx => {
        if (kind === 'registration_create') {
          await tx.run('INSERT INTO accounts (id,username,user_handle,created_at) VALUES (?,?,?,?)',
            [pending.user_id, pending.username, pending.user_handle, Date.now()]);
          await seedFictionalItems(tx, pending.user_id, pending.username);
        } else {
          const exists = await tx.one('SELECT id FROM accounts WHERE id=?', [pending.user_id]);
          if (!exists) throw httpError(403, '등록 계정이 존재하지 않습니다.');
        }
        await tx.run(`INSERT INTO passkeys
          (id,user_id,name,public_key,counter,transports,device_type,backed_up,created_at,last_used_at)
          VALUES (?,?,?,?,?,?,?,?,?,?)`, [
          saved.id, pending.user_id, pending.passkey_name,
          Buffer.from(saved.publicKey).toString('base64url'), saved.counter,
          JSON.stringify(saved.transports || credential.response?.transports || []),
          credentialDeviceType || null, credentialBackedUp ? 1 : 0, Date.now(), null,
        ]);
      });
    } catch (e) {
      if (String(e.message).includes('UNIQUE') || String(e.code) === '23505') {
        throw httpError(409, '계정명 또는 패스키가 이미 등록되어 있습니다.');
      }
      throw e;
    }
    if (kind === 'registration_create') {
      await revokeSession(store, req.sessionToken);
      res.cookie(SESSION_COOKIE, await createSession(store, pending.user_id), cookieSettings(secure));
    }
    res.status(201).json({ verified: true, account: pending.username, passkeyName: pending.passkey_name });
  });

  app.post('/api/authentication/options', async (req, res) => {
    const username = normalizeName(req.body?.username).toLowerCase();
    if (!isUsername(username)) throw httpError(400, '계정 이름을 확인해 주세요.');
    const user = await store.one('SELECT id,username FROM accounts WHERE username=?', [username]);
    if (!user) throw httpError(404, '계정 또는 등록된 패스키를 찾을 수 없습니다.');
    const passkeys = await store.all('SELECT id,transports FROM passkeys WHERE user_id=?', [user.id]);
    if (!passkeys.length) throw httpError(403, '등록된 패스키가 없어 로그인할 수 없습니다.');
    const options = await wa.generateAuthenticationOptions({
      rpID, userVerification: 'required', timeout: 60_000,
      allowCredentials: passkeys.map(k => ({ id: k.id, transports: JSON.parse(k.transports) })),
    });
    const ticket = await issueChallenge(store, { kind: 'authentication', challenge: options.challenge, userId: user.id });
    res.json({ ticket, options });
  });

  app.post('/api/authentication/verify', async (req, res) => {
    const { ticket, credential } = req.body || {};
    const pending = await consumeChallenge(store, ticket, 'authentication');
    if (!pending) throw httpError(409, '챌린지가 이미 사용되었거나 만료되었습니다.');
    if (!credential || typeof credential.id !== 'string') throw httpError(400, '인증기 응답이 올바르지 않습니다.');
    const key = await store.one('SELECT * FROM passkeys WHERE id=? AND user_id=?', [credential.id, pending.user_id]);
    if (!key) throw httpError(403, '이 계정에 등록되지 않았거나 삭제된 패스키입니다.');
    let result;
    try {
      result = await wa.verifyAuthenticationResponse({
        response: credential, expectedChallenge: pending.challenge,
        expectedOrigin: origin, expectedRPID: rpID,
        requireUserVerification: true,
        credential: {
          id: key.id,
          publicKey: new Uint8Array(Buffer.from(key.public_key, 'base64url')),
          counter: Number(key.counter), transports: JSON.parse(key.transports),
        },
      });
    } catch {
      throw httpError(401, '서명·챌린지·출처 또는 인증기 카운터 검증에 실패했습니다.');
    }
    if (!result.verified) throw httpError(401, '서명 검증에 실패했습니다.');
    // 서명 확인을 통과한 경우에만 카운터 갱신. 동시 갱신 경합은 실패로 처리.
    const updated = await store.run(
      'UPDATE passkeys SET counter=?, last_used_at=? WHERE id=? AND user_id=? AND counter=?',
      [result.authenticationInfo.newCounter, Date.now(), key.id, pending.user_id, key.counter]
    );
    if (updated !== 1) throw httpError(409, '다른 인증 요청과 충돌했습니다. 다시 로그인하세요.');
    await revokeSession(store, req.sessionToken);
    res.cookie(SESSION_COOKIE, await createSession(store, pending.user_id), cookieSettings(secure));
    res.json({ verified: true, username: (await store.one('SELECT username FROM accounts WHERE id=?', [pending.user_id]))?.username });
  });

  app.post('/api/logout', async (req, res) => {
    await revokeSession(store, req.sessionToken);
    res.clearCookie(SESSION_COOKIE, { path: '/', sameSite: 'lax', secure });
    res.json({ loggedOut: true });
  });

  app.get('/api/passkeys', async (req, res) => {
    const account = requireAccount(req);
    const keys = await store.all('SELECT id,name,public_key,counter,transports,device_type,backed_up,created_at,last_used_at FROM passkeys WHERE user_id=? ORDER BY created_at ASC', [account.id]);
    res.json({ account: account.username, passkeys: keys.map(k => ({
      id: k.id, name: k.name, publicKeyBase64URL: k.public_key,
      publicKeyDescription: '서버에 저장된 공개키(COSE 인코딩, base64url). 개인키·비밀번호 아님',
      counter: Number(k.counter), transports: JSON.parse(k.transports),
      deviceType: k.device_type, backedUp: !!k.backed_up,
      createdAt: Number(k.created_at), lastUsedAt: k.last_used_at ? Number(k.last_used_at) : null,
    })) });
  });
  app.delete('/api/passkeys/:id', async (req, res) => {
    const account = requireAccount(req);
    const status = await deleteCredentialKeepingOne(store, account.id, req.params.id);
    if (status === 'not_found') throw httpError(404, '등록된 패스키가 없습니다.');
    if (status === 'last_key') throw httpError(409, '마지막 패스키는 삭제할 수 없습니다. 먼저 새 패스키를 등록하세요.');
    res.json({ deleted: true });
  });

  const respondPrivate = async (req, res, explicitUser) => {
    const account = requireAccount(req);
    // URL로 타인 계정 ID를 직접 지정하면 403, 쿼리의 accountId는 신뢰하지 않음.
    if (explicitUser && explicitUser !== account.id) throw httpError(403, '다른 계정의 비공개 자료를 열람할 수 없습니다.');
    const items = await store.all('SELECT id,title,content,created_at FROM private_items WHERE user_id=? ORDER BY created_at', [account.id]);
    res.json({ userId: account.id, username: account.username, count: items.length, items });
  };
  app.get('/api/private', (req, res) => respondPrivate(req, res, null));
  app.get('/api/private/:userId', (req, res) => respondPrivate(req, res, req.params.userId));

  app.get('/vendor/webauthn.js', (_req, res) => res.sendFile(path.join(baseDir, 'node_modules', '@simplewebauthn', 'browser', 'dist', 'bundle', 'index.umd.min.js')));
  app.get('/', (_req, res) => res.sendFile(originalHtml));
  app.use('/public', express.static(publicDir, { index: false, maxAge: 0 }));
  app.use('/api', (_req, _res, next) => next(httpError(404, 'API 경로가 존재하지 않습니다.')));
  app.use((error, req, res, _next) => {
    const status = error.status || (error.type === 'entity.too.large' ? 413 : error instanceof SyntaxError ? 400 : 500);
    if (status >= 500) console.error('[Task8]', error);
    const explanation = status >= 500 ? '서버 오류가 발생했습니다.'
      : error instanceof SyntaxError ? '요청 JSON 형식이 올바르지 않습니다.' : error.message;
    res.status(status).json({ error: explanation });
  });
  return { app, db: store, origin, rpID };
}
