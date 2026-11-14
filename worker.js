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
    .sort(([a],[b])=>a < b ? -1 : a > b ? 1 : 0).map(([key,value])=>key+'='+value).join('\n');
  const secret=await hmac(encoder.encode('WebAppData'),env.TELEGRAM_BOT_TOKEN);
  if(hex(await hmac(secret,check))!==receivedHash.toLowerCase()) return null;
  try{
    const user=JSON.parse(params.get('user')||'null');
    if(!user || !user.id) return null;
    return user;
  }catch{return null;}
}

const SKINS=[{"id":"mint","name":"М’ятка","price":5},{"id":"ocean","name":"Океан","price":5},{"id":"sunset","name":"Захід","price":6},{"id":"lavender","name":"Лаванда","price":6},{"id":"flame","name":"Полум’я","price":7},{"id":"forest","name":"Лісовик","price":7},{"id":"galaxy","name":"Космос","price":8},{"id":"neon","name":"Неон","price":8},{"id":"rainbow","name":"Веселка","price":10},{"id":"crown","name":"Королівський","price":50},{"id":"admin","name":"Адмінський","price":2000},{"id":"creator","name":"Скін творця","price":10000},{"id":"glass","name":"Кристал","price":25},{"id":"robot","name":"Робот","price":5},{"id":"ninja","name":"Ніндзя","price":6},{"id":"alien","name":"Прибулець","price":7},{"id":"pirate","name":"Пірат","price":8},{"id":"knight","name":"Лицар","price":9},{"id":"panda","name":"Панда","price":5},{"id":"fox","name":"Лисичка","price":6},{"id":"astronaut","name":"Космонавт","price":10},{"id":"slime","name":"Слайм","price":7},{"id":"dragon","name":"Дракончик","price":10},{"id":"skeleton","name":"Скелет","price":150},{"id":"santa","name":"Дід Мороз","price":200},{"id":"saint","name":"Св. Миколай","price":150},{"id":"kapitoshka","name":"Капітошка","price":20},{"id":"lich","name":"Ліч — Жнець","price":250}];
async function ensureShopTables(env){
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS player_skins (telegram_id TEXT NOT NULL, skin_id TEXT NOT NULL, purchased_at TEXT DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (telegram_id,skin_id))").run();
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS player_skin_selection (telegram_id TEXT PRIMARY KEY, skin_id TEXT NOT NULL DEFAULT 'default', updated_at TEXT DEFAULT CURRENT_TIMESTAMP)").run();
 await env.DB.prepare("CREATE TABLE IF NOT EXISTS skin_purchases (id TEXT PRIMARY KEY, telegram_id TEXT NOT NULL, skin_id TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', invoice_url TEXT, telegram_charge_id TEXT UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP, paid_at TEXT)").run();
}
async function botCall(env,method,payload){
 const response=await fetch('https://api.telegram.org/bot'+env.TELEGRAM_BOT_TOKEN+'/'+method,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.description||('Telegram '+method+' failed'));return data.result;
}
async function grantSkin(env,purchaseId,telegramId,payment){
 const row=await env.DB.prepare('SELECT * FROM skin_purchases WHERE id=?').bind(purchaseId).first();
 if(!row||row.status==='paid'||String(row.telegram_id)!==String(telegramId)||payment.currency!=='XTR'||Number(payment.total_amount)!==Number(row.amount))return false;
 await env.DB.prepare("INSERT OR IGNORE INTO player_skins(telegram_id,skin_id) VALUES(?,?)").bind(row.telegram_id,row.skin_id).run();
 await env.DB.prepare("UPDATE skin_purchases SET status='paid',telegram_charge_id=?,paid_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(payment.telegram_payment_charge_id||null,purchaseId).run();
 return true;
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

   if(url.pathname==='/api/telegram/webhook' && request.method==='POST'){
    if(!env.TELEGRAM_WEBHOOK_SECRET || request.headers.get('X-Telegram-Bot-Api-Secret-Token')!==env.TELEGRAM_WEBHOOK_SECRET) return json({error:'Unauthorized'},401,origin);
    const update=await request.json();
    if(update.pre_checkout_query){
      const q=update.pre_checkout_query, row=await env.DB.prepare('SELECT * FROM skin_purchases WHERE id=?').bind(q.invoice_payload).first();
      const valid=row&&row.status==='pending'&&String(row.telegram_id)===String(q.from.id)&&q.currency==='XTR'&&Number(q.total_amount)===Number(row.amount);
      await botCall(env,'answerPreCheckoutQuery',{pre_checkout_query_id:q.id,ok:!!valid,error_message:valid?undefined:'Покупка недійсна. Спробуй ще раз.'});
    }
    const payment=update.message?.successful_payment;
    if(payment){
      const buyer=update.message.from?.id;
      await grantSkin(env,payment.invoice_payload,buyer,payment);
    }
    return json({ok:true},200,origin);
   }

   // WebRTC signaling only: game-state traffic stays on direct peer connections.
   const roomMatch=url.pathname.match(/^\/api\/mp\/signal\/([A-Z0-9]{6})$/);
   if(roomMatch && request.headers.get('Upgrade')?.toLowerCase()==='websocket'){
    const token=url.searchParams.get('token')||'';
    const telegramId=await verifyToken(env,token);
    if(!telegramId) return json({error:'Потрібно увійти через Telegram'},401,origin);
    const actor=await env.DB.prepare('SELECT telegram_id,username,first_name,last_name FROM players WHERE telegram_id=?').bind(String(telegramId)).first();
    if(!actor) return json({error:'Профіль гравця не знайдено'},401,origin);
    const role=url.searchParams.get('role')||'client';
    if(!['host','client'].includes(role)) return json({error:'Некоректна роль кімнати'},400,origin);
    const name=[actor.first_name,actor.last_name].filter(Boolean).join(' ')||actor.username||'Гравець';
    const id=env.ROOMS.idFromName(roomMatch[1]);
    const stub=env.ROOMS.get(id);
    const target=new URL(request.url);
    target.searchParams.delete('token');
    target.searchParams.set('peer',crypto.randomUUID());
    target.searchParams.set('name',name.slice(0,48));
    return stub.fetch(new Request(target.toString(),request));
   }

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

   if(url.pathname==='/api/admin/payments/setup' && request.method==='POST'){
    const actor=await currentPlayer(request,env);
    if(!actor || actor.role!=='creator') return json({error:'Лише творець може налаштувати оплату'},403,origin);
    if(!env.TELEGRAM_WEBHOOK_SECRET) return json({error:'Додай Worker variable TELEGRAM_WEBHOOK_SECRET перед налаштуванням'},400,origin);
    const result=await botCall(env,'setWebhook',{url:new URL('/api/telegram/webhook',request.url).toString(),secret_token:env.TELEGRAM_WEBHOOK_SECRET,allowed_updates:['pre_checkout_query','message'],drop_pending_updates:false});
    return json({ok:true,result},200,origin);
   }
   if(url.pathname==='/api/shop/me' && request.method==='GET'){
    const actor=await currentPlayer(request,env);if(!actor)return json({error:'Потрібно увійти через Telegram'},401,origin);
    await ensureShopTables(env);
    // Творець і адміністратори отримують усі скіни без оплати.
    if(actor.role==='creator'||actor.role==='admin'){
      for(const skin of SKINS){
        await env.DB.prepare('INSERT OR IGNORE INTO player_skins(telegram_id,skin_id) VALUES(?,?)').bind(actor.telegram_id,skin.id).run();
      }
    }
    const owned=await env.DB.prepare('SELECT skin_id FROM player_skins WHERE telegram_id=?').bind(actor.telegram_id).all();
    const selected=await env.DB.prepare('SELECT skin_id FROM player_skin_selection WHERE telegram_id=?').bind(actor.telegram_id).first();
    return json({skins:SKINS,owned:owned.results.map(x=>x.skin_id),selected:selected?.skin_id||'default'},200,origin);
   }
   if(url.pathname==='/api/shop/select' && request.method==='POST'){
    const actor=await currentPlayer(request,env);if(!actor)return json({error:'Потрібно увійти через Telegram'},401,origin);
    await ensureShopTables(env);const body=await request.json(),id=String(body.skinId||'');
    if(id!=='default'&&!SKINS.some(x=>x.id===id))return json({error:'Невідомий скін'},400,origin);
    if(id!=='default'){
      const owned=await env.DB.prepare('SELECT 1 AS ok FROM player_skins WHERE telegram_id=? AND skin_id=?').bind(actor.telegram_id,id).first();
      if(!owned)return json({error:'Цей скін ще не куплений'},403,origin);
    }
    await env.DB.prepare("INSERT INTO player_skin_selection(telegram_id,skin_id) VALUES(?,?) ON CONFLICT(telegram_id) DO UPDATE SET skin_id=excluded.skin_id,updated_at=CURRENT_TIMESTAMP").bind(actor.telegram_id,id).run();
    return json({ok:true,selected:id},200,origin);
   }
   if(url.pathname==='/api/shop/buy' && request.method==='POST'){
    const actor=await currentPlayer(request,env);if(!actor)return json({error:'Потрібно увійти через Telegram'},401,origin);
    await ensureShopTables(env);const body=await request.json(),skin=SKINS.find(x=>x.id===String(body.skinId||''));
    if(!skin)return json({error:'Невідомий скін'},400,origin);
    const owned=await env.DB.prepare('SELECT 1 AS ok FROM player_skins WHERE telegram_id=? AND skin_id=?').bind(actor.telegram_id,skin.id).first();
    if(owned)return json({error:'Цей скін уже куплений'},409,origin);
    const purchaseId=crypto.randomUUID();
    await env.DB.prepare("INSERT INTO skin_purchases(id,telegram_id,skin_id,amount,status) VALUES(?,?,?,?,'pending')").bind(purchaseId,actor.telegram_id,skin.id,skin.price).run();
    try{
      const invoice=await botCall(env,'createInvoiceLink',{title:'Скін: '+skin.name,description:'Ексклюзивний вигляд персонажа у ДЖАМПЕРІ',payload:purchaseId,provider_token:'',currency:'XTR',prices:[{label:'Скін '+skin.name,amount:skin.price}]});
      await env.DB.prepare('UPDATE skin_purchases SET invoice_url=? WHERE id=?').bind(invoice,purchaseId).run();
      return json({invoiceUrl:invoice,purchaseId},200,origin);
    }catch(e){
      await env.DB.prepare("UPDATE skin_purchases SET status='failed' WHERE id=?").bind(purchaseId).run();throw e;
    }
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


/**
 * One Durable Object per room. It only forwards SDP/ICE signaling messages;
 * gameplay state must travel directly over WebRTC data channels.
 */
export class MultiplayerRoom {
 constructor(ctx, env){this.ctx=ctx;this.env=env;}
 async fetch(request){
  if(request.headers.get('Upgrade')?.toLowerCase()!=='websocket') return new Response('WebSocket required',{status:426});
  const url=new URL(request.url),peer=url.searchParams.get('peer')||'',role=url.searchParams.get('role')||'client';
  const name=(url.searchParams.get('name')||'Гравець').slice(0,48);
  if(!/^[0-9a-f-]{36}$/i.test(peer)||!['host','client'].includes(role)) return new Response('Bad request',{status:400});
  const sockets=this.ctx.getWebSockets();
  const members=sockets.map(ws=>ws.deserializeAttachment()).filter(Boolean);
  if(members.some(m=>m.peer===peer)) return new Response('Already connected',{status:409});
  const host=members.find(m=>m.role==='host');
  if(role==='host' && host) return new Response('Room already has a host',{status:409});
  if(role==='client' && !host) return new Response('Host is not connected',{status:404});
  if(members.length>=5) return new Response('Room is full',{status:409});
  const pair=new WebSocketPair(),client=pair[0],server=pair[1];
  server.serializeAttachment({peer,role,name});
  this.ctx.acceptWebSocket(server);
  const current=[...members,{peer,role,name}];
  this.send(server,{type:'welcome',self:peer,role,players:current.map(({peer,role,name})=>({peer,role,name}))});
  this.broadcast({type:'player-joined',player:{peer,role,name}},server);
  return new Response(null,{status:101,webSocket:client});
 }
 send(ws,data){try{ws.send(JSON.stringify(data));}catch{}}
 broadcast(data,except=null){for(const ws of this.ctx.getWebSockets()){if(ws!==except)this.send(ws,data);}}
 webSocketMessage(ws,raw){
  if(typeof raw!=='string'||raw.length>20000){try{ws.close(1009,'Message too large');}catch{}return;}
  let msg;try{msg=JSON.parse(raw);}catch{return;}
  const sender=ws.deserializeAttachment();if(!sender)return;
  if(msg.type!=='signal'||!['offer','answer','ice'].includes(msg.signalType))return;
  if(msg.data==null||JSON.stringify(msg.data).length>16000)return;
  const target=String(msg.to||'');
  const recipient=this.ctx.getWebSockets().find(other=>{
   const meta=other.deserializeAttachment();return meta&&meta.peer===target;
  });
  if(!recipient)return;
  // Only the host may initiate offers; clients may answer or send ICE.
  if(msg.signalType==='offer'&&sender.role!=='host')return;
  if(msg.signalType==='answer'&&sender.role!=='client')return;
  this.send(recipient,{type:'signal',from:sender.peer,signalType:msg.signalType,data:msg.data});
 }
 webSocketClose(ws,code,reason,wasClean){
  const meta=ws.deserializeAttachment();if(!meta)return;
  if(meta.role==='host'){
   for(const other of this.ctx.getWebSockets()){try{other.close(1000,'Host left');}catch{}}
   return;
  }
  this.broadcast({type:'player-left',peer:meta.peer});
 }
 webSocketError(ws,error){this.webSocketClose(ws,1011,'socket error',false);}
}
