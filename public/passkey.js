'use strict';
// 이 스크립트에는 비공개 자료가 없습니다. /api/private 응답에서만 가져옵니다.
(() => {
  const root = document.querySelector('[data-task8-passkey-addon="true"]');
  if (!root) return;
  const $ = selector => root.querySelector(selector);
  const status = $('#task8-status');
  const guest = $('#task8-guest');
  const member = $('#task8-member');
  let backendReady = false;
  let webauthnLoading;

  function show(text, level = 'info') {
    status.textContent = text;
    status.className = 'task8-message' + (level === 'error' ? ' is-error' : level === 'success' ? ' is-success' : '');
  }
  function element(tag, text) {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    return el;
  }
  async function api(route, method = 'GET', body) {
    const response = await fetch('/api' + route, {
      method, credentials: 'same-origin', cache: 'no-store',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`${result.error || '서버 요청 오류'} (HTTP ${response.status})`);
    return result;
  }
  async function ensureWebAuthn() {
    if (!window.isSecureContext || !window.PublicKeyCredential) {
      throw new Error('패스키는 HTTPS 또는 localhost와 WebAuthn 지원 기기에서만 동작합니다.');
    }
    if (!webauthnLoading) {
      webauthnLoading = new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = '/vendor/webauthn.js';
        script.onload = resolve;
        script.onerror = () => reject(new Error('브라우저용 WebAuthn 라이브러리를 불러오지 못했습니다.'));
        document.head.append(script);
      });
    }
    await webauthnLoading;
    if (!window.SimpleWebAuthnBrowser) throw new Error('패스키 라이브러리가 없습니다.');
    return window.SimpleWebAuthnBrowser;
  }
  async function register(mode, username, passkeyName) {
    const browser = await ensureWebAuthn();
    const { ticket, options } = await api('/registration/options', 'POST', { mode, username, passkeyName });
    let credential;
    try {
      credential = await browser.startRegistration({ optionsJSON: options });
    } catch (error) {
      await api('/ceremony/cancel', 'POST', { ticket }).catch(() => {});
      throw error;
    }
    await api('/registration/verify', 'POST', { ticket, mode, credential });
  }
  async function login(username) {
    const browser = await ensureWebAuthn();
    const { ticket, options } = await api('/authentication/options', 'POST', { username });
    let credential;
    try {
      credential = await browser.startAuthentication({ optionsJSON: options });
    } catch (error) {
      await api('/ceremony/cancel', 'POST', { ticket }).catch(() => {});
      throw error;
    }
    await api('/authentication/verify', 'POST', { ticket, credential });
  }
  function niceError(error) {
    if (['NotAllowedError', 'AbortError'].includes(error?.name)) return '패스키 대화상자가 취소되거나 인증 시간이 초과되었습니다. 등록 내역은 저장되지 않았습니다.';
    if (error?.name === 'InvalidStateError') return '해당 인증기에는 동일한 패스키가 이미 등록되어 있을 수 있습니다. 다른 인증기나 저장소를 선택하세요.';
    return error?.message || '요청에 실패했습니다.';
  }
  async function busy(form, fn) {
    if (!backendReady) { show('인증 서버가 연결되지 않았습니다.', 'error'); return; }
    const buttons = [...form.querySelectorAll('button')];
    buttons.forEach(x => { x.disabled = true; });
    try { await fn(); }
    catch (error) { show(niceError(error), 'error'); }
    finally { buttons.forEach(x => { x.disabled = false; }); }
  }
  const date = value => new Intl.DateTimeFormat('ko-KR', { dateStyle:'medium', timeZone:'Asia/Seoul' }).format(new Date(value));
  async function renderMember() {
    const [data, keys] = await Promise.all([api('/private'), api('/passkeys')]);
    const items = $('#task8-items');
    items.replaceChildren();
    for (const item of data.items) {
      const article = element('article'); article.className = 'task8-record';
      article.append(element('h4', item.title), element('p', item.content));
      items.append(article);
    }
    const list = $('#task8-keys');
    list.replaceChildren();
    for (const key of keys.passkeys) {
      const row = element('div'); row.className = 'task8-keyrow';
      const info = element('div'); info.append(element('strong', key.name), element('small', `등록: ${date(key.createdAt)}`));
      const del = element('button', '삭제'); del.type = 'button'; del.className = 'task8-delete';
      del.disabled = keys.passkeys.length < 2;
      del.title = del.disabled ? '마지막 패스키는 삭제할 수 없습니다.' : '이 패스키 삭제';
      del.addEventListener('click', async () => {
        if (!window.confirm('이 패스키를 삭제하시겠습니까?')) return;
        del.disabled = true;
        try { await api(`/passkeys/${encodeURIComponent(key.id)}`, 'DELETE'); await renderMember(); show('패스키를 삭제했습니다. 남은 패스키로 계속 로그인할 수 있습니다.', 'success'); }
        catch (error) { show(niceError(error), 'error'); del.disabled = false; }
      });
      row.append(info, del);
      const details = element('details'); details.className = 'task8-keydetails';
      details.append(element('summary', '서버에 저장한 공개키 보기 (개인키 아님)'), element('code', key.publicKeyBase64URL));
      list.append(row, details);
    }
  }
  async function refresh() {
    const { loggedIn, account } = await api('/me');
    guest.hidden = loggedIn;
    member.hidden = !loggedIn;
    if (!loggedIn) {
      $('#task8-items').replaceChildren(); $('#task8-keys').replaceChildren();
      $('#task8-username').textContent = ''; $('#task8-userid').textContent = '';
      return;
    }
    $('#task8-username').textContent = account.username;
    $('#task8-userid').textContent = account.id;
    await renderMember();
  }
  $('#task8-create-form').addEventListener('submit', event => {
    event.preventDefault(); const form = event.currentTarget;
    busy(form, async () => {
      await register('create', $('#task8-create-name').value.trim().toLowerCase(), $('#task8-create-label').value.trim());
      await refresh(); show('첫 번째 패스키 등록 완료. 두 번째 패스키도 등록해 보세요.', 'success');
    });
  });
  $('#task8-login-form').addEventListener('submit', event => {
    event.preventDefault(); const form = event.currentTarget;
    busy(form, async () => {
      await login($('#task8-login-name').value.trim().toLowerCase());
      await refresh(); show('패스키 서명이 검증되어 본인 자료를 열었습니다.', 'success');
    });
  });
  $('#task8-add-form').addEventListener('submit', event => {
    event.preventDefault(); const form = event.currentTarget;
    busy(form, async () => {
      await register('add', undefined, $('#task8-add-label').value.trim());
      await renderMember(); form.reset(); show('추가 패스키가 등록되었습니다.', 'success');
    });
  });
  $('#task8-logout').addEventListener('click', async () => {
    try { await api('/logout','POST'); await refresh(); show('로그아웃되었습니다. 이전 세션은 더 이상 유효하지 않습니다.', 'success'); }
    catch(error) { show(niceError(error),'error'); }
  });
  (async () => {
    try {
      const health = await api('/health');
      if (!health.ok) throw new Error('인증 서버 상태 오류');
      backendReady = true;
      await refresh();
      show('인증 서버가 연결되었습니다. 패스키를 등록하거나 로그인할 수 있습니다.');
    } catch (_error) {
      backendReady = false;
      for (const button of root.querySelectorAll('form button')) button.disabled = true;
      show('이 주소에서는 패스키 인증 서버가 제공되지 않습니다. GitHub Pages는 정적 페이지이므로, 설정된 Vercel HTTPS 배포 주소에서 패스키 기능을 이용해야 합니다. 공개 자기소개는 그대로 열람할 수 있습니다.', 'error');
    }
  })();
})();
