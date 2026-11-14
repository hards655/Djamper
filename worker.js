const encoder = new TextEncoder();
const json = (data, status=200, origin='*') => new Response(JSON.stringify(data), {
  status, headers: {'content-type':'application/json; charset=utf-8','access-control-allow-origin':origin,
  'access-control-allow-methods':'GET,POST,OPTIONS','access-control-allow-headers':'Content-Type,Authorization',
  'vary':'Origin'}
});
async function sha256(data){return crypto.subtle.digest('SHA-256', data);}
async function hmac(keyBytes, message){
  const key=await crypto.subtle.importKey('raw',keyBytes,{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC',key,encoder.encode(message)));
}
function hex(bytes){return [...bytes].map(b=>b.toString(16).padStart(2,'0')).join('');}
function b64url(bytes){let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function issueToken(env, telegramId){
  const payload=b64url(encoder.encode(JSON.stringify({sub:String(telegramId),exp:Date.now()+30*24*3600*1000})));
  const sig=await hmac(encoder.encode(env.SESSION_SECRET),payload);
  return payload+'.'+b64url(sig);
}
async function verifyToken(env, token){
  if(!token) return null;
  const [payload,sig]=token.split('.'); if(!payload||!sig)return null;
  const expected=b64url(await hmac(encoder.encode(env.SESSION_SECRET),payload));
  if(expected!==sig)return null;
  try{const p=JSON.parse(atob(payload.replace(/-/g,'+').replace(/_/g,'/')));if(p.exp<Date.now())return null;return p.sub;}catch{return null;}
}
async function verifyTelegram(env, initData){
  if(!initData || typeof initData!=='string' || initData.length>8192) return null;
  const params=new URLSearchParams(initData);
  const receivedHash=params.get('hash');
  const authDate=Number(params.get('auth_date'));
  if(!receivedHash || !Number.isFinite(authDate) || authDate>Date.now()/1000+60 || Date.now()/1000-authDate>86400) return null;
  const check=[...params.entries()].filter(([key])=>key!=='hash')
    .sort(([a],[b])=>a.localeCompare(b)).map(([key,value])=>key+'='+value).join('\\n');
  const secret=await hmac(encoder.encode(env.TELEGRAM_BOT_TOKEN),'WebAppData');
  if(hex(await hmac(secret,check))!==receivedHash.toLowerCase()) return null;
  try{
    const user=JSON.parse(params.get('user')||'null');
    if(!user || !user.id) return null;
    return user;
  }catch{return null;}
}
function originAllowed(request, env){
  const origin=request.headers.get('Origin')||'';
  const allowed=(env.ALLOWED_ORIGINS||'').split(',').map(x=>x.trim()).filter(Boolean);
  return allowed.includes(origin)?origin:'null';
}
async function currentPlayer(request,env){
  const token=(request.headers.get('Authorization')||'').replace(/^Bearer\s+/i,'');
  const id=await verifyToken(env,token); if(!id)return null;
  return await env.DB.prepare('SELECT telegram_id,role FROM players WHERE telegram_id=?').bind(String(id)).first();
}
export default {
 async fetch(request,env){
  const origin=originAllowed(request,env);
  if(request.method==='OPTIONS') return new Response(null,{status:204,headers:{
    'access-control-allow-origin':origin,'access-control-allow-methods':'GET,POST,OPTIONS',
    'access-control-allow-headers':'Content-Type,Authorization','vary':'Origin'}});
  const url=new URL(request.url);
  try{
   if(url.pathname==='/api/health' && request.method==='GET') return json({ok:true},200,origin);
   if(url.pathname==='/api/auth' && request.method==='POST'){
    const body=await request.json();
    const user=await verifyTelegram(env,body.initData);
    if(!user) return json({error:'Telegram Mini App initData недійсний або застарілий'},401,origin);
    const id=String(user.id);
    await env.DB.prepare(`INSERT INTO players(telegram_id,username,first_name,last_name,photo_url)
      VALUES(?,?,?,?,?) ON CONFLICT(telegram_id) DO UPDATE SET username=excluded.username,
      first_name=excluded.first_name,last_name=excluded.last_name,photo_url=excluded.photo_url,updated_at=CURRENT_TIMESTAMP`)
      .bind(id,user.username||null,user.first_name||null,user.last_name||null,user.photo_url||null).run();
    if(String(env.CREATOR_TELEGRAM_ID||'')===id){
      await env.DB.prepare("UPDATE players SET role='creator',updated_at=CURRENT_TIMESTAMP WHERE telegram_id=?").bind(id).run();
    }
    const player=await env.DB.prepare('SELECT telegram_id,username,first_name,last_name,photo_url,best_score,games,role FROM players WHERE telegram_id=?').bind(id).first();
    return json({token:await issueToken(env,id),user:player},200,origin);
   }
   if(url.pathname==='/api/leaderboard' && request.method==='GET'){
    const limit=Math.min(100,Math.max(1,Number(url.searchParams.get('limit')||100)));
    const count=await env.DB.prepare('SELECT COUNT(*) AS n FROM players').first();
    const rows=await env.DB.prepare(`SELECT username,first_name,last_name,photo_url,best_score,games,role
      FROM players ORDER BY best_score DESC, updated_at ASC LIMIT ?`).bind(limit).all();
    return json({total:count.n,players:rows.results},200,origin);
   }
   if(url.pathname==='/api/score' && request.method==='POST'){
    const player=await currentPlayer(request,env); if(!player)return json({error:'Потрібно увійти через Telegram'},401,origin);
    const body=await request.json(), score=Number(body.score);
    if(!Number.isSafeInteger(score)||score<0||score>10000000) return json({error:'Некоректний результат'},400,origin);
    await env.DB.prepare(`UPDATE players SET best_score=MAX(best_score,?),games=games+1,updated_at=CURRENT_TIMESTAMP WHERE telegram_id=?`).bind(score,player.telegram_id).run();
    const row=await env.DB.prepare('SELECT best_score FROM players WHERE telegram_id=?').bind(player.telegram_id).first();
    return json({ok:true,best:row?.best_score||0},200,origin);
   }
   if(url.pathname==='/api/admin/players' && request.method==='GET'){
    const actor=await currentPlayer(request,env);
    if(!actor || actor.role!=='creator') return json({error:'Ця панель доступна лише творцю гри'},403,origin);
    const rows=await env.DB.prepare(`SELECT telegram_id,username,first_name,last_name,role
      FROM players ORDER BY CASE role WHEN 'creator' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, first_name COLLATE NOCASE`).all();
    return json({players:rows.results},200,origin);
   }
   if(url.pathname==='/api/admin/role' && request.method==='POST'){
    const actor=await currentPlayer(request,env);
    if(!actor || actor.role!=='creator') return json({error:'Лише творець може призначати адміністраторів'},403,origin);
    const body=await request.json(), target=String(body.telegram_id||''), role=body.role;
    if(!/^\d{1,24}$/.test(target) || !['admin','player'].includes(role)) return json({error:'Некоректний гравець або роль'},400,origin);
    if(target===String(env.CREATOR_TELEGRAM_ID||'')) return json({error:'Роль творця не можна змінити'},400,origin);
    const result=await env.DB.prepare('UPDATE players SET role=?,updated_at=CURRENT_TIMESTAMP WHERE telegram_id=?').bind(role,target).run();
    if(!result.meta || result.meta.changes===0) return json({error:'Гравця не знайдено. Він має хоча б раз увійти в гру.'},404,origin);
    return json({ok:true},200,origin);
   }
   return json({error:'Not found'},404,origin);
  }catch(e){return json({error:'Server error',detail:env.ENVIRONMENT==='development'?String(e):undefined},500,origin);}
 }
};
