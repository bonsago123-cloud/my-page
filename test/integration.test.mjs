import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const base = path.dirname(fileURLToPath(import.meta.url));
const source = path.resolve(base, '..');
const patcher = path.join(source,'scripts','apply-task8.mjs');
const client = fs.readFileSync(path.join(source,'public','passkey.js'),'utf8');
const server = fs.readFileSync(path.join(source,'src','app.mjs'),'utf8');
const fixture = `<!doctype html>
<html><head><style>:root{--bg:#fff}</style></head>
<body><div class="nav-links"><a href="#evidence">근거</a></div>
<main><section id="activity"><p>실제 원본 공개 내용 A</p></section><section id="evidence"><p>실제 원본 공개 내용 B</p></section></main>
<script>window.originalSiteFeature = true;</script></body></html>`;

test('원본의 공개 콘텐츠·스크립트·CSS를 유지하고 추가 영역만 삽입한다', () => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'my-page-t08-'));
  try {
    fs.writeFileSync(path.join(temp,'index.html'),fixture);
    execFileSync(process.execPath, [patcher],{cwd:temp});
    const html = fs.readFileSync(path.join(temp,'index.html'),'utf8');
    assert.match(html, /실제 원본 공개 내용 A/);
    assert.match(html, /실제 원본 공개 내용 B/);
    assert.match(html, /window\.originalSiteFeature = true/);
    assert.match(html, /:root\{--bg:#fff\}/);
    assert.match(html, /<a href="#passkey">비공개 영역<\/a>/);
    assert.match(html, /data-task8-passkey-addon="true"/);
    assert.match(html, /<script src="\.\/public\/passkey\.js" defer><\/script>/);
    assert.doesNotMatch(html, /type=["']password["']/i);
    execFileSync(process.execPath, [patcher],{cwd:temp});
    assert.equal(fs.readFileSync(path.join(temp,'index.html'),'utf8'),html,'재실행 시 중복 삽입되지 않아야 함');
    assert.equal(fs.readFileSync(path.join(temp,'index.task8-original.html.bak'),'utf8'),fixture,'원본 백업 보관');
  } finally { fs.rmSync(temp,{recursive:true,force:true}); }
});
test('원본 구조가 다른 경우 수정하지 않는다',()=>{
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'my-page-t08-invalid-'));
  try {
    const html='<html><body>관계없는 사이트</body></html>';
    fs.writeFileSync(path.join(temp,'index.html'),html);
    assert.throws(()=>execFileSync(process.execPath,[patcher],{cwd:temp,stdio:'pipe'}));
    assert.equal(fs.readFileSync(path.join(temp,'index.html'),'utf8'),html);
  } finally {fs.rmSync(temp,{recursive:true,force:true});}
});
test('클라이언트 HTML/JS에는 가상 비공개 데이터 원문이 포함되지 않는다',()=>{
  for(const phrase of ['별빛 도서관의 익명 도서 추천','미래연구소, 푸른연구소','오늘 패킷 전달 경로를 가상 실습']){
    assert.ok(!client.includes(phrase));
    assert.ok(!fs.readFileSync(patcher,'utf8').includes(phrase));
  }
  assert.ok(client.includes("api('/private')"));
});
test('WebAuthn 인증 서버는 실제 검증기, 사용자 DB 필터, 원본 HTML 및 CSP 해시가 있다',()=>{
  assert.match(server,/verifyRegistrationResponse\(/);
  assert.match(server,/verifyAuthenticationResponse\(/);
  assert.match(server,/WHERE user_id=\?/);
  assert.match(server,/readFileSync\(originalHtml/);
  assert.match(server,/sha256-/);
  assert.match(server,/express\.static\(publicDir/);
  assert.doesNotMatch(server,/app\.use\(express\.static\(baseDir/);
});
