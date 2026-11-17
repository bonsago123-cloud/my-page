import { randomUUID } from 'node:crypto';
import { digest, now, randomToken } from './security.mjs';
export const CHALLENGE_TTL_MS = 5 * 60_000;
export const SESSION_TTL_MS = 12 * 60 * 60_000;

export async function issueChallenge(db, values) {
  const ticket = randomToken();
  const issued = now();
  await db.run('DELETE FROM challenges WHERE expires_at<?', [issued]);
  await db.run('DELETE FROM sessions WHERE expires_at<?', [issued]);
  await db.run(
    `INSERT INTO challenges (ticket_hash,kind,challenge,user_id,username,user_handle,passkey_name,created_at,expires_at)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [digest(ticket), values.kind, values.challenge, values.userId ?? null,
      values.username ?? null, values.userHandle ?? null, values.passkeyName ?? null,
      issued, issued + CHALLENGE_TTL_MS]
  );
  return ticket;
}

// 원자적 DELETE...RETURNING: 한 티켓은 성공/실패 여부와 무관하게 한 번만 소비됨.
export async function consumeChallenge(db, ticket, kind) {
  if (typeof ticket !== 'string' || !/^[A-Za-z0-9_-]{40,64}$/.test(ticket)) return null;
  const row = await db.one(
    'DELETE FROM challenges WHERE ticket_hash=? AND kind=? AND expires_at>? RETURNING *',
    [digest(ticket), kind, now()]
  );
  return row;
}

export async function cancelChallenge(db, ticket) {
  if (typeof ticket !== 'string' || !/^[A-Za-z0-9_-]{40,64}$/.test(ticket)) return;
  await db.run('DELETE FROM challenges WHERE ticket_hash=?', [digest(ticket)]);
}

export async function createSession(db, userId) {
  const token = randomToken();
  const created = now();
  await db.run('INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES (?,?,?,?)',
    [digest(token), userId, created, created + SESSION_TTL_MS]);
  return token;
}

export async function lookupSession(db, token) {
  if (!token || !/^[A-Za-z0-9_-]{40,64}$/.test(token)) return null;
  return db.one(
    `SELECT a.id, a.username FROM sessions s JOIN accounts a ON a.id=s.user_id
     WHERE s.token_hash=? AND s.expires_at>?`,
    [digest(token), now()]
  );
}

export async function revokeSession(db, token) {
  if (token) await db.run('DELETE FROM sessions WHERE token_hash=?', [digest(token)]);
}

export async function seedFictionalItems(tx, accountId, username = `가상-${accountId.slice(0, 8)}`) {
  const sample = [
    ['가상 프로젝트 구상', `예시: ${username} 계정이 별빛 도서관의 익명 도서 추천 기능을 만든다는 가상의 계획입니다.`],
    ['가상 지원 목록', `예시: ${username} 계정의 미래연구소, 푸른연구소, 달빛연구소는 실존하는 지원처가 아닌 예시입니다.`],
    ['가상 회고', `예시: ${username} 계정은 오늘 패킷 전달 경로를 가상 실습으로 조사했다고 가정했습니다.`],
  ];
  for (const [title, content] of sample) {
    await tx.run('INSERT INTO private_items (id,user_id,title,content,created_at) VALUES (?,?,?,?,?)',
      [randomUUID(), accountId, title, content, now()]);
  }
}

export async function deleteCredentialKeepingOne(db, userId, credentialId) {
  return db.transaction(async tx => {
    if (tx.kind === 'postgres') {
      // 동시 삭제를 직렬화: 마지막 두 키가 동시에 지워지는 경쟁 조건 방지
      await tx.one('SELECT id FROM accounts WHERE id=? FOR UPDATE', [userId]);
    }
    const keys = await tx.all('SELECT id FROM passkeys WHERE user_id=?', [userId]);
    if (!keys.some(k => k.id === credentialId)) return 'not_found';
    if (keys.length <= 1) return 'last_key';
    await tx.run('DELETE FROM passkeys WHERE user_id=? AND id=?', [userId, credentialId]);
    return 'deleted';
  });
}
