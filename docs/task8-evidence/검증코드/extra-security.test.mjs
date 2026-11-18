// 과제 8: 별도 임시 DB에서 운영 코드의 API 핸들러와 서비스 함수를 HTTP로 검증.
// 실제 WebAuthn 서명 검증은 모의 처리됨. 테스트 시 node_modules에는 실제 Express 필요. 운영 DB 수정 없음.
import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import {randomUUID,randomBytes} from 'node:crypto';
import {createApp} from '../src/app.mjs';
import {seedFictionalItems,createSession} from '../src/services.mjs';

const origin='http://localhost:3000';
const dbFolder=fs.mkdtempSync(path.join(os.tmpdir(),'task8-security-'));
const fakeAuthenticator={
  async generateAuthenticationOptions(){return {challenge:randomBytes(32).toString('base64url'),allowCredentials:[]}},
  async generateRegistrationOptions(){return {challenge:randomBytes(32).toString('base64url')}},
  async verifyAuthenticationResponse({response}){
    if(response.fakeSignature!=='test-ok')throw Error('invalid mock proof');
    return {verified:true,authenticationInfo:{newCounter:1}};
  },
  async verifyRegistrationResponse(){throw Error('unused in this test')}
};
let db,server,base,ids={},cookies={};
async function send(route,{method='GET',cookie,body}={}){
  const headers={};if(cookie)headers.cookie=`passkey_session=${cookie}`;
  if(body!==undefined)headers['content-type']='application/json';
  if(method!=='GET')headers.origin=origin;
  const response=await fetch(base+route,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  const text=await response.text();let data;try{data=JSON.parse(text)}catch{data={raw:text}}
  return {status:response.status,data,cookie:response.headers.get('set-cookie')};
}

// 테스트는 이 파일 전체를 한 번 실행하여 독립 DB를 만든 뒤 지움.
test.before(async()=>{
  const app=await createApp({config:{ORIGIN:origin,RP_ID:'localhost',SQLITE_PATH:path.join(dbFolder,'test.sqlite')},webauthn:fakeAuthenticator});
  db=app.db;server=app.app.listen(0,'127.0.0.1');
  await new Promise(resolve=>server.once('listening',resolve));
  base=`http://127.0.0.1:${server.address().port}`;
  for(const username of ['alpha-lab','beta-lab']){
    const id=randomUUID();ids[username]=id;
    await db.run('INSERT INTO accounts (id,username,user_handle,created_at) VALUES (?,?,?,?)',[id,username,randomUUID(),Date.now()]);
    await seedFictionalItems(db,id,username);
    cookies[username]=await createSession(db,id);
    await db.run(`INSERT INTO passkeys (id,user_id,name,public_key,counter,transports,backed_up,created_at) VALUES (?,?,?,?,?,?,?,?)`,[`fixture-key-${username}`,id,'가상 테스트 인증기','AQID',0,'[]',0,Date.now()]);
  }
});
test.after(async()=>{await new Promise(resolve=>server.close(resolve));await db.close();fs.rmSync(dbFolder,{recursive:true,force:true})});

test('챌린지: 로그인 요청 두 번에서 매번 달라지고, 사용한 ticket 재사용은 HTTP 409',async()=>{
  const username='alpha-lab';
  const first=await send('/api/authentication/options',{method:'POST',body:{username}});
  const second=await send('/api/authentication/options',{method:'POST',body:{username}});
  assert.equal(first.status,200);assert.equal(second.status,200);
  assert.notEqual(first.data.options.challenge,second.data.options.challenge);
  const credential={id:'fixture-key-alpha-lab',fakeSignature:'test-ok'};
  const ok=await send('/api/authentication/verify',{method:'POST',body:{ticket:first.data.ticket,credential}});
  assert.equal(ok.status,200);assert.equal(ok.data.verified,true);
  const replay=await send('/api/authentication/verify',{method:'POST',body:{ticket:first.data.ticket,credential}});
  assert.equal(replay.status,409);
  assert.match(replay.data.error,/이미 사용되었거나 만료/);
  console.log('[CHALLENGE]',JSON.stringify({options_1:first.status,options_2:second.status,unique:true,verify_first:ok.status,verify_replay:replay.status,replay_error:replay.data.error,signature_verification:'mocked_for_this_test'}));
});

test('A/B 교차 접근: 각자 3건 200, 양방향 HTTP 403, 전후 자료 건수 유지',async()=>{
  const A='alpha-lab',B='beta-lab';
  const beforeA=await send('/api/private',{cookie:cookies[A]});
  const beforeB=await send('/api/private',{cookie:cookies[B]});
  assert.equal(beforeA.status,200);assert.equal(beforeB.status,200);
  assert.equal(beforeA.data.count,3);assert.equal(beforeB.data.count,3);
  assert.notEqual(beforeA.data.userId,beforeB.data.userId);
  const aToB=await send('/api/private/'+ids[B],{cookie:cookies[A]});
  const bToA=await send('/api/private/'+ids[A],{cookie:cookies[B]});
  assert.equal(aToB.status,403);assert.equal(bToA.status,403);
  const queryA=await send('/api/private?accountId='+ids[B],{cookie:cookies[A]});
  const queryB=await send('/api/private?accountId='+ids[A],{cookie:cookies[B]});
  assert.equal(queryA.status,200);assert.equal(queryB.status,200);
  assert.equal(queryA.data.userId,ids[A]);assert.equal(queryB.data.userId,ids[B]);
  const afterA=await send('/api/private',{cookie:cookies[A]});
  const afterB=await send('/api/private',{cookie:cookies[B]});
  assert.equal(afterA.data.count,3);assert.equal(afterB.data.count,3);
  const unauth=await send('/api/private/'+ids[B]);assert.equal(unauth.status,401);
  console.log('[CROSS_ACCOUNT]',JSON.stringify({A_own:beforeA.status,A_to_B:aToB.status,B_own:beforeB.status,B_to_A:bToA.status,query_override_A:queryA.data.username,query_override_B:queryB.data.username,A_count_before:beforeA.data.count,A_count_after:afterA.data.count,B_count_before:beforeB.data.count,B_count_after:afterB.data.count,unauth:unauth.status}));
});
