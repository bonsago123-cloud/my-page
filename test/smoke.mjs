// npm run start 후 실행: node test/smoke.mjs http://localhost:3000
const base = process.argv[2] || 'http://localhost:3000';
let ok = 0;
async function inspect(path, expected, options = {}) {
  const res = await fetch(base + path, options);
  const json = await res.json();
  if (res.status !== expected) throw new Error(`${path}: ${res.status} / expected ${expected}: ${JSON.stringify(json)}`);
  console.log(`PASS ${res.status} ${path}`, json.error || '');
  ok++;
  return json;
}
await inspect('/api/health', 200);
await inspect('/api/me', 200);
await inspect('/api/private', 401);
await inspect('/api/private/fictional', 401);
await inspect('/api/passkeys', 401);
const headers = { 'Content-Type': 'application/json', Origin: base };
await inspect('/api/authentication/verify', 409, { method: 'POST', headers, body: JSON.stringify({ ticket: 'invalid', credential: { id: 'fake' } }) });
await inspect('/api/registration/verify', 409, { method: 'POST', headers, body: JSON.stringify({ ticket: 'invalid', mode: 'create' }) });
const wrongOrigin = { 'Content-Type': 'application/json', Origin: 'https://attacker.invalid' };
await inspect('/api/authentication/options', 403, { method: 'POST', headers: wrongOrigin, body: JSON.stringify({ username: 'alpha' }) });
console.log(`HTTP 스모크 테스트 ${ok}개 통과. 실제 Windows Hello/휴대폰 등록·서명은 브라우저로 수동 확인 필요.`);
