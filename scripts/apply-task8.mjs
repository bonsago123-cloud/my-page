import fs from 'node:fs';
import path from 'node:path';

// 실행 위치: GitHub 저장소 bonsago123-cloud/my-page 의 루트
const root = path.resolve(process.cwd());
const htmlFile = path.join(root, 'index.html');
if (!fs.existsSync(htmlFile)) {
  throw new Error('원본 index.html이 없습니다. my-page 저장소 루트에서 npm run apply를 실행하세요.');
}
const original = fs.readFileSync(htmlFile, 'utf8');
if (original.includes('data-task8-passkey-addon="true"')) {
  console.log('이미 과제 8 패스키 확장이 적용되어 있습니다. 원본을 다시 수정하지 않습니다.');
  process.exit(0);
}
const required = [
  '<div class="nav-links">',
  '<a href="#evidence">근거</a>',
  '<section id="activity"',
  '<section id="evidence"',
  '</main>',
  '</body>',
  '</head>',
];
for (const key of required) {
  if (!original.includes(key)) {
    throw new Error(`원본 구조가 예상과 다릅니다: ${key}를 찾지 못했습니다. 안전을 위해 수정하지 않았습니다.`);
  }
}
const panel = `
    <!-- T08-C13~53: 새 기능만 추가. 위 공개 자기소개 원본은 그대로 유지. -->
    <section id="passkey" class="task8" aria-labelledby="task8-title" data-task8-passkey-addon="true">
      <div class="task8-heading">
        <p class="task8-kicker">과제 8 · PRIVATE AREA</p>
        <h2 id="task8-title">패스키로 보호되는 비공개 영역</h2>
        <p>위 자기소개는 누구나 볼 수 있습니다. 아래 비공개 기록은 인증기에 저장한 패스키로 로그인한 사용자에게만 서버가 전달합니다.</p>
      </div>
      <p id="task8-status" class="task8-message" role="status" aria-live="polite">인증 서버 상태를 확인하는 중입니다.</p>
      <div id="task8-guest" class="task8-grid">
        <div class="task8-card">
          <h3>기존 계정 로그인</h3>
          <p>패스키의 공개키로 서버가 서명을 검증합니다.</p>
          <form id="task8-login-form">
            <label for="task8-login-name">가상 계정 이름</label>
            <input id="task8-login-name" type="text" minlength="3" maxlength="24" pattern="[a-z0-9-]+" placeholder="예: starlab" autocomplete="username" required>
            <button type="submit">패스키로 로그인</button>
          </form>
        </div>
        <div class="task8-card">
          <h3>새 계정과 첫 패스키</h3>
          <p>실제 개인정보는 입력하지 마세요. 가상의 이름만 사용합니다.</p>
          <form id="task8-create-form">
            <label for="task8-create-name">가상 계정 이름</label>
            <input id="task8-create-name" type="text" minlength="3" maxlength="24" pattern="[a-z0-9-]+" placeholder="예: starlab" autocomplete="off" required>
            <label for="task8-create-label">패스키 별명</label>
            <input id="task8-create-label" type="text" maxlength="48" placeholder="예: 집 컴퓨터" required>
            <button type="submit">첫 패스키 등록</button>
          </form>
        </div>
      </div>
      <div id="task8-member" hidden>
        <div class="task8-userline">
          <div><h3><span id="task8-username"></span> 계정의 비공개 기록</h3><p>아래 내용은 공개 HTML이 아니라, 로그인한 세션의 사용자 ID로 서버에서 조회한 가상 자료입니다.</p></div>
          <button id="task8-logout" type="button">로그아웃</button>
        </div>
        <div class="task8-grid">
          <div class="task8-card"><h3>비공개 기록</h3><div id="task8-items"></div></div>
          <div class="task8-card">
            <h3>등록된 패스키</h3><div id="task8-keys"></div>
            <form id="task8-add-form">
              <label for="task8-add-label">두 번째 패스키 별명</label>
              <input id="task8-add-label" type="text" maxlength="48" placeholder="예: 스마트폰 / 보안 키" required>
              <button type="submit">패스키 추가</button>
            </form>
            <p class="task8-note">패스키가 1개만 남았다면 삭제할 수 없습니다. 등록된 패스키를 모두 분실하면 이 실습 계정으로 로그인할 수 없습니다.</p>
          </div>
        </div>
        <p class="task8-note">계정 ID (상호 접근 차단 실습): <code id="task8-userid"></code></p>
      </div>
      <p class="task8-note">패스키의 개인키는 인증기/저장소 밖으로 전달되지 않습니다. 등록이 취소되면 서버에 패스키를 저장하지 않습니다. 모든 비공개 예시는 가상 자료입니다.</p>
    </section>
`;
let changed = original;
changed = changed.replace('<a href="#evidence">근거</a>', '<a href="#evidence">근거</a>\n          <a href="#passkey">비공개 영역</a>');
changed = changed.replace('</head>', '  <link rel="stylesheet" href="./public/passkey.css">\n</head>');
changed = changed.replace('</main>', `${panel}\n  </main>`);
changed = changed.replace('</body>', '  <script src="./public/passkey.js" defer></script>\n</body>');
if (changed === original) throw new Error('변경 내용이 없습니다.');
// 내용을 먼저 완성하고 원본을 한 번에 교체. 실패 시 백업 보존.
const backupPath = path.join(root, 'index.task8-original.html.bak');
if (!fs.existsSync(backupPath)) fs.writeFileSync(backupPath, original, 'utf8');
const tempPath = htmlFile + '.task8.tmp';
fs.writeFileSync(tempPath, changed, 'utf8');
fs.renameSync(tempPath, htmlFile);
console.log('기존 소개 원문을 유지하고 비공개 영역·링크·스크립트만 추가했습니다.');
console.log(`백업: ${path.relative(root, backupPath)}`);
