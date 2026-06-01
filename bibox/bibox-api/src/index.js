async function hashPassword(password) {
  const data = new TextEncoder().encode(password);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function generateToken() {
  const arr = new Uint8Array(32); crypto.getRandomValues(arr);
  return Array.from(arr).map(b=>b.toString(16).padStart(2,'0')).join('');
}
function corsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '*';
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
    'Access-Control-Allow-Credentials': 'true',
  };
}
function json(data, status=200, request=null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(request) }
  });
}
function err(msg, status=400, request=null) { return json({ok:false,error:msg}, status, request); }

async function getUser(request, db) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ','').trim();
  if (!token) return null;
  await db.prepare('UPDATE sessions SET last_seen=CURRENT_TIMESTAMP WHERE token=?').bind(token).run();
  return await db.prepare('SELECT u.* FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=?').bind(token).first();
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    if (path === '/register' && method === 'POST') {
      const {username,email,password} = await request.json();
      if (!username||!email||!password) return err('Заполни все поля',400,request);
      if (username.length<3) return err('Логин минимум 3 символа',400,request);
      if (password.length<4) return err('Пароль минимум 4 символа',400,request);
      const existing = await env.bibox_db.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
      if (existing) return err('Пользователь уже существует',400,request);
      const hash = await hashPassword(password);
      const result = await env.bibox_db.prepare('INSERT INTO users (username,email,password_hash,bix) VALUES (?,?,?,10)').bind(username,email,hash).run();
      const userId = result.meta.last_row_id;
      await env.bibox_db.prepare('INSERT INTO avatars (user_id) VALUES (?)').bind(userId).run();
      await env.bibox_db.prepare('INSERT INTO clicker (user_id) VALUES (?)').bind(userId).run();
      const token = generateToken();
      await env.bibox_db.prepare('INSERT INTO sessions (token,user_id) VALUES (?,?)').bind(token,userId).run();
      return json({ok:true,token,username,bix:10}, 200, request);
    }

    if (path === '/login' && method === 'POST') {
      const {username,password} = await request.json();
      if (!username||!password) return err('Заполни все поля',400,request);
      const user = await env.bibox_db.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
      if (!user) return err('Неверный логин или пароль',400,request);
      const hash = await hashPassword(password);
      if (hash !== user.password_hash) return err('Неверный логин или пароль',400,request);
      const token = generateToken();
      await env.bibox_db.prepare('INSERT INTO sessions (token,user_id) VALUES (?,?)').bind(token,user.id).run();
      return json({ok:true,token,username:user.username,bix:user.bix}, 200, request);
    }

    if (path === '/profile' && method === 'GET') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const avatar = await env.bibox_db.prepare('SELECT * FROM avatars WHERE user_id=?').bind(user.id).first();
      const inventory = await env.bibox_db.prepare('SELECT item_id,equipped FROM inventory WHERE user_id=?').bind(user.id).all();
      const clicker = await env.bibox_db.prepare('SELECT * FROM clicker WHERE user_id=?').bind(user.id).first();
      const friends = await env.bibox_db.prepare('SELECT u.username FROM friends f JOIN users u ON f.friend_id=u.id WHERE f.user_id=?').bind(user.id).all();
      const requests = await env.bibox_db.prepare('SELECT u.username FROM friend_requests fr JOIN users u ON fr.from_id=u.id WHERE fr.to_id=?').bind(user.id).all();
      return json({ok:true,username:user.username,bix:user.bix,avatar:avatar||{},inventory:inventory.results||[],clicker:clicker?{clicks:clicker.clicks,click_power:clicker.click_power,cps:clicker.cps,upgrades:JSON.parse(clicker.upgrades||'{}'),total_bix:clicker.total_bix}:{},friends:friends.results||[],friend_requests:requests.results||[]}, 200, request);
    }

    if (path === '/avatar' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {body,hair,cloth} = await request.json();
      await env.bibox_db.prepare('INSERT INTO avatars (user_id,body,hair,cloth) VALUES (?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET body=excluded.body,hair=excluded.hair,cloth=excluded.cloth').bind(user.id,body,hair,cloth).run();
      return json({ok:true}, 200, request);
    }

    if (path === '/buy' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {item_id,price} = await request.json();
      const existing = await env.bibox_db.prepare('SELECT id FROM inventory WHERE user_id=? AND item_id=?').bind(user.id,item_id).first();
      if (existing) return err('Уже куплено',400,request);
      if (price>0) {
        if (user.bix<price) return err('Недостаточно Bix',400,request);
        await env.bibox_db.prepare('UPDATE users SET bix=bix-? WHERE id=?').bind(price,user.id).run();
      }
      await env.bibox_db.prepare('INSERT INTO inventory (user_id,item_id) VALUES (?,?)').bind(user.id,item_id).run();
      const updated = await env.bibox_db.prepare('SELECT bix FROM users WHERE id=?').bind(user.id).first();
      return json({ok:true,bix:updated.bix}, 200, request);
    }

    if (path === '/equip' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {item_id,equipped} = await request.json();
      await env.bibox_db.prepare('UPDATE inventory SET equipped=? WHERE user_id=? AND item_id=?').bind(equipped?1:0,user.id,item_id).run();
      return json({ok:true}, 200, request);
    }

    if (path === '/clicker' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {clicks,click_power,cps,upgrades,total_bix} = await request.json();
      await env.bibox_db.prepare('INSERT INTO clicker (user_id,clicks,click_power,cps,upgrades,total_bix) VALUES (?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET clicks=excluded.clicks,click_power=excluded.click_power,cps=excluded.cps,upgrades=excluded.upgrades,total_bix=excluded.total_bix').bind(user.id,clicks,click_power,cps,JSON.stringify(upgrades),total_bix).run();
      return json({ok:true}, 200, request);
    }

    if (path === '/bix/add' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {amount} = await request.json();
      if (!amount||amount<=0) return err('Неверное количество',400,request);
      await env.bibox_db.prepare('UPDATE users SET bix=bix+? WHERE id=?').bind(amount,user.id).run();
      const updated = await env.bibox_db.prepare('SELECT bix FROM users WHERE id=?').bind(user.id).first();
      return json({ok:true,bix:updated.bix}, 200, request);
    }

    if (path === '/bix/spend' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {amount} = await request.json();
      if (user.bix<amount) return err('Недостаточно Bix',400,request);
      await env.bibox_db.prepare('UPDATE users SET bix=bix-? WHERE id=?').bind(amount,user.id).run();
      const updated = await env.bibox_db.prepare('SELECT bix FROM users WHERE id=?').bind(user.id).first();
      return json({ok:true,bix:updated.bix}, 200, request);
    }

    if (path === '/friends/request' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {username} = await request.json();
      if (username===user.username) return err('Нельзя добавить себя',400,request);
      const target = await env.bibox_db.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
      if (!target) return err('Пользователь не найден',400,request);
      const alreadyFriend = await env.bibox_db.prepare('SELECT id FROM friends WHERE user_id=? AND friend_id=?').bind(user.id,target.id).first();
      if (alreadyFriend) return err('Уже в друзьях',400,request);
      const alreadyReq = await env.bibox_db.prepare('SELECT id FROM friend_requests WHERE from_id=? AND to_id=?').bind(user.id,target.id).first();
      if (alreadyReq) return err('Запрос уже отправлен',400,request);
      const friendCount = await env.bibox_db.prepare('SELECT COUNT(*) as cnt FROM friends WHERE user_id=?').bind(user.id).first();
      if (friendCount.cnt>=10) return err('Максимум 10 друзей',400,request);
      await env.bibox_db.prepare('INSERT INTO friend_requests (from_id,to_id) VALUES (?,?)').bind(user.id,target.id).run();
      return json({ok:true}, 200, request);
    }

    if (path === '/friends/accept' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {username} = await request.json();
      const from = await env.bibox_db.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
      if (!from) return err('Пользователь не найден',400,request);
      await env.bibox_db.prepare('DELETE FROM friend_requests WHERE from_id=? AND to_id=?').bind(from.id,user.id).run();
      await env.bibox_db.prepare('INSERT OR IGNORE INTO friends (user_id,friend_id) VALUES (?,?)').bind(user.id,from.id).run();
      await env.bibox_db.prepare('INSERT OR IGNORE INTO friends (user_id,friend_id) VALUES (?,?)').bind(from.id,user.id).run();
      return json({ok:true}, 200, request);
    }

    if (path === '/friends/decline' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {username} = await request.json();
      const from = await env.bibox_db.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
      if (!from) return err('Пользователь не найден',400,request);
      await env.bibox_db.prepare('DELETE FROM friend_requests WHERE from_id=? AND to_id=?').bind(from.id,user.id).run();
      return json({ok:true}, 200, request);
    }

    if (path === '/friends/remove' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {username} = await request.json();
      const target = await env.bibox_db.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
      if (!target) return err('Пользователь не найден',400,request);
      await env.bibox_db.prepare('DELETE FROM friends WHERE (user_id=? AND friend_id=?) OR (user_id=? AND friend_id=?)').bind(user.id,target.id,target.id,user.id).run();
      return json({ok:true}, 200, request);
    }

    if (path === '/user/search' && method === 'GET') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const q = url.searchParams.get('q')||'';
      if (!q) return err('Введи ник',400,request);
      const target = await env.bibox_db.prepare('SELECT id,username,bix FROM users WHERE username=?').bind(q).first();
      if (!target) return json({ok:true,found:false}, 200, request);
      const avatar = await env.bibox_db.prepare('SELECT * FROM avatars WHERE user_id=?').bind(target.id).first();
      const inventory = await env.bibox_db.prepare('SELECT item_id,equipped FROM inventory WHERE user_id=?').bind(target.id).all();
      const isFriend = await env.bibox_db.prepare('SELECT id FROM friends WHERE user_id=? AND friend_id=?').bind(user.id,target.id).first();
      const hasPending = await env.bibox_db.prepare('SELECT id FROM friend_requests WHERE from_id=? AND to_id=?').bind(user.id,target.id).first();
      return json({ok:true,found:true,username:target.username,bix:target.bix,avatar:avatar||{},inventory:inventory.results||[],is_friend:!!isFriend,has_pending:!!hasPending,is_self:target.id===user.id}, 200, request);
    }

    if (path === '/bix/send' && method === 'POST') {
      const user = await getUser(request, env.bibox_db);
      if (!user) return err('Не авторизован',401,request);
      const {username,amount} = await request.json();
      if (!amount||amount<=0) return err('Неверное количество',400,request);
      if (user.bix<amount) return err('Недостаточно Bix',400,request);
      if (username===user.username) return err('Нельзя отправить себе',400,request);
      const target = await env.bibox_db.prepare('SELECT id FROM users WHERE username=?').bind(username).first();
      if (!target) return err('Пользователь не найден',400,request);
      await env.bibox_db.prepare('UPDATE users SET bix=bix-? WHERE id=?').bind(amount,user.id).run();
      await env.bibox_db.prepare('UPDATE users SET bix=bix+? WHERE id=?').bind(amount,target.id).run();
      const updated = await env.bibox_db.prepare('SELECT bix FROM users WHERE id=?').bind(user.id).first();
      return json({ok:true,bix:updated.bix}, 200, request);
    }

    if (path === '/admin/stats' && method === 'GET') {
      const key = url.searchParams.get('key')||'';
      if (key!=='bobix_admin_2025') return err('Нет доступа',403,request);
      const totalUsers = await env.bibox_db.prepare('SELECT COUNT(*) as cnt FROM users').first();
      const onlineUsers = await env.bibox_db.prepare("SELECT COUNT(DISTINCT user_id) as cnt FROM sessions WHERE last_seen >= datetime('now','-5 minutes')").first();
      return json({ok:true,total_users:totalUsers.cnt,online_now:onlineUsers.cnt}, 200, request);
    }

    return err('Не найдено',404,request);
  }
};
