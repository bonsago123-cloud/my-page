import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { openDatabase } from '../src/db.mjs';
import { digest, isUsername, constantTimeEqual } from '../src/security.mjs';
import {
  consumeChallenge, issueChallenge, createSession, lookupSession,
  revokeSession, seedFictionalItems, deleteCredentialKeepingOne
} from '../src/services.mjs';

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'task8-'));
let db;
test.before(async () => { db = await openDatabase({ SQLITE_PATH: path.join(temp, 'test.sqlite') }); });
test.after(async () => { await db?.close(); fs.rmSync(temp, { force: true, recursive: true }); });

async function makeUser(username) {
  const id = randomUUID();
  await db.run('INSERT INTO accounts (id,username,user_handle,created_at) VALUES (?,?,?,?)',
    [id, username, randomUUID(), Date.now()]);
  return id;
}
async function addKey(user, id) {
  await db.run('INSERT INTO passkeys (id,user_id,name,public_key,counter,transports,backed_up,created_at) VALUES (?,?,?,?,?,?,?,?)',
    [id, user, '테스트 키', 'cGxhY2Vob2xkZXI', 0, '[]', 0, Date.now()]);
}

test('챌린지는 요청마다 다른 티켓으로 발급되고 원자적으로 1회만 소비된다', async () => {
  const userId = await makeUser('first-account');
  const a = await issueChallenge(db, { kind: 'authentication', challenge: 'challenge_A', userId });
  const b = await issueChallenge(db, { kind: 'authentication', challenge: 'challenge_B', userId });
  assert.notEqual(a, b);
  const [first, replay] = await Promise.all([
    consumeChallenge(db, a, 'authentication'),
    consumeChallenge(db, a, 'authentication'),
  ]);
  assert.equal([first, replay].filter(Boolean).length, 1);
  assert.equal((first || replay).challenge, 'challenge_A');
  assert.equal(await consumeChallenge(db, a, 'authentication'), null);
  assert.equal((await consumeChallenge(db, b, 'authentication')).challenge, 'challenge_B');
});

test('챌린지 종류가 다르면 소모하지 않고 만료된 챌린지는 수락하지 않는다', async () => {
  const ticket = await issueChallenge(db, { kind: 'registration_add', challenge: 'reg1' });
  assert.equal(await consumeChallenge(db, ticket, 'authentication'), null);
  assert.equal((await consumeChallenge(db, ticket, 'registration_add')).challenge, 'reg1');
  const old = await issueChallenge(db, { kind: 'authentication', challenge: 'reg2' });
  await db.run('UPDATE challenges SET expires_at=? WHERE ticket_hash=?', [Date.now() - 10, digest(old)]);
  assert.equal(await consumeChallenge(db, old, 'authentication'), null);
});

test('세션은 원문 대신 SHA256 해시로 저장되고 로그아웃 즉시 무효화된다', async () => {
  const user = await makeUser('second-account');
  const session = await createSession(db, user);
  assert.equal((await lookupSession(db, session)).id, user);
  assert.equal(await db.one('SELECT token_hash FROM sessions WHERE token_hash=?', [session]), null);
  assert.equal((await db.one('SELECT token_hash FROM sessions WHERE token_hash=?', [digest(session)])).token_hash, digest(session));
  await revokeSession(db, session);
  assert.equal(await lookupSession(db, session), null);
});

test('개인별 가상 비공개 자료는 서로 다르게 격리돼 있다', async () => {
  const a = await makeUser('archive-alpha');
  const b = await makeUser('archive-beta');
  await seedFictionalItems(db, a);
  await seedFictionalItems(db, b);
  const beforeA = await db.all('SELECT * FROM private_items WHERE user_id=?', [a]);
  const beforeB = await db.all('SELECT * FROM private_items WHERE user_id=?', [b]);
  assert.equal(beforeA.length, 3);
  assert.equal(beforeB.length, 3);
  assert.ok(beforeA.every(item => item.user_id === a));
  assert.ok(beforeB.every(item => item.user_id === b));
  assert.equal((await db.all('SELECT * FROM private_items WHERE user_id=?', [b])).length, beforeB.length);
});

test('마지막 키 삭제는 차단되며 두 키 중 하나 삭제는 성공한다', async () => {
  const user = await makeUser('third-account');
  await addKey(user, 'testkey1');
  assert.equal(await deleteCredentialKeepingOne(db, user, 'testkey1'), 'last_key');
  await addKey(user, 'testkey2');
  assert.equal(await deleteCredentialKeepingOne(db, user, 'testkey1'), 'deleted');
  assert.equal(await deleteCredentialKeepingOne(db, user, 'testkey1'), 'not_found');
  assert.equal((await db.all('SELECT * FROM passkeys WHERE user_id=?', [user])).length, 1);
  assert.equal(await deleteCredentialKeepingOne(db, user, 'testkey2'), 'last_key');
});

test('두 키를 동시에 삭제하려 해도 마지막 하나는 남는다', async () => {
  const user = await makeUser('parallel-account');
  await addKey(user, 'parallel-1');
  await addKey(user, 'parallel-2');
  const results = await Promise.all([
    deleteCredentialKeepingOne(db, user, 'parallel-1'),
    deleteCredentialKeepingOne(db, user, 'parallel-2'),
  ]);
  assert.ok(results.includes('deleted'));
  assert.ok(results.includes('last_key'));
  assert.equal((await db.all('SELECT * FROM passkeys WHERE user_id=?', [user])).length, 1);
});

test('계정 이름 검증과 안전한 상수 시간 문자열 비교', () => {
  assert.equal(isUsername('abc'), true);
  assert.equal(isUsername('a'), false);
  assert.equal(isUsername('abc-123'), true);
  assert.equal(isUsername('ABC'), false);
  assert.equal(constantTimeEqual('abc', 'abc'), true);
  assert.equal(constantTimeEqual('abc', 'abd'), false);
});
