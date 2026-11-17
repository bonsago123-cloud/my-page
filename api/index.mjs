import { createApp } from '../src/app.mjs';
// Vercel 서버리스 인스턴스 내에서는 Promise를 재사용; 영속 자료는 Postgres에만 저장.
const initialized = createApp();
export default async function handler(req, res) {
  const { app } = await initialized;
  return app(req, res);
}
