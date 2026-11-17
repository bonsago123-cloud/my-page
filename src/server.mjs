import { createApp } from './app.mjs';
const { app, origin } = await createApp();
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`과제8 실행: ${origin} (localhost:${port})`));
