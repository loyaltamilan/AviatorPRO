const http=require('http'),fs=require('fs'),path=require('path'),c=require('crypto');
const PORT=process.env.PORT||3000,F=path.join(__dirname,'data.json'),TTL=8*3600e3;
let db=fs.existsSync(F)?JSON.parse(fs.readFileSync(F)):{keys:[],sessions:{},results:[],nid:1};
const save=()=>fs.writeFileSync(F,JSON.stringify(db));
const hash=(k,s)=>c.scryptSync(String(k),s,32).toString('hex');
function addKey(key,label,admin){const salt=c.randomBytes(16).toString('hex');db.keys.push({id:c.randomUUID(),salt,hash:hash(key,salt),label,active:true,admin:!!admin,created:Date.now()});save();}
if(!db.keys.length){if(!process.env.ADMIN_KEY){console.error('First run: set ADMIN_KEY env var');process.exit(1)}addKey(process.env.ADMIN_KEY,'Owner',true);}
const tries={};
const send=(r,code,o,h={})=>{r.writeHead(code,{'Content-Type':'application/json',...h});r.end(JSON.stringify(o))};
const body=q=>new Promise(r=>{let b='';q.on('data',d=>{b+=d;if(b.length>3e6)q.destroy()});q.on('end',()=>{try{r(JSON.parse(b||'{}'))}catch{r({})}})});
function sess(q){const m=/sid=([a-f0-9]+)/.exec(q.headers.cookie||'');const s=m&&db.sessions[m[1]];if(!s)return null;
 if(s.exp<Date.now()){delete db.sessions[m[1]];return null}const k=db.keys.find(k=>k.id===s.kid);if(!k||!k.active)return null;return{...s,sid:m[1],admin:k.admin}}
const num=v=>{v=+v;return Number.isFinite(v)&&v>=1&&v<=1e6?Math.round(v*100)/100:null};
http.createServer(async(q,r)=>{
 const u=new URL(q.url,'http://x'),p=u.pathname,m=q.method;
 try{
 if(!p.startsWith('/api/')){const f=p==='/'?'index.html':p.slice(1);const fp=path.join(__dirname,'public',path.normalize(f).replace(/^(\.\.[\/\\])+/,''));
  if(!fp.startsWith(path.join(__dirname,'public'))||!fs.existsSync(fp))return r.writeHead(404).end();
  r.writeHead(200,{'Content-Type':'text/html','X-Content-Type-Options':'nosniff'});return r.end(fs.readFileSync(fp))}
 if(p==='/api/login'&&m==='POST'){
  const ip=q.socket.remoteAddress,t=tries[ip]||(tries[ip]={n:0,t:Date.now()});if(Date.now()-t.t>9e5){t.n=0;t.t=Date.now()}
  if(t.n>=8)return send(r,429,{error:'Too many attempts. Try later.'});
  const {key}=await body(q);let hit=null;
  for(const k of db.keys){const a=Buffer.from(hash(key||'',k.salt),'hex'),b=Buffer.from(k.hash,'hex');if(c.timingSafeEqual(a,b)&&k.active)hit=k}
  await new Promise(s=>setTimeout(s,700));
  if(!hit){t.n++;return send(r,401,{error:'Invalid access key'})}
  const sid=c.randomBytes(24).toString('hex');db.sessions[sid]={kid:hit.id,label:hit.label,created:Date.now(),exp:Date.now()+TTL};save();
  return send(r,200,{ok:true,admin:hit.admin},{'Set-Cookie':`sid=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${TTL/1000}`});}
 const s=sess(q);if(!s)return send(r,401,{error:'Unauthorized'});
 if(p==='/api/me')return send(r,200,{label:s.label,admin:s.admin,exp:s.exp});
 if(p==='/api/logout'){delete db.sessions[s.sid];save();return send(r,200,{ok:1},{'Set-Cookie':'sid=; Max-Age=0; Path=/'})}
 const mine=db.results.filter(x=>x.k===s.kid);
 if(p==='/api/results'){
  if(m==='GET')return send(r,200,mine.map(({id,m,t,src})=>({id,m,t,src})));
  if(m==='POST'){const b=await body(q),v=num(b.m);if(!v)return send(r,400,{error:'Multiplier must be a number ≥ 1.00'});
   const x={id:db.nid++,k:s.kid,m:v,t:b.t||Date.now(),src:'manual'};db.results.push(x);save();return send(r,200,x)}
  if(m==='DELETE'){db.results=db.results.filter(x=>x.k!==s.kid);save();return send(r,200,{ok:1})}}
 if(p==='/api/results/import'&&m==='POST'){const b=await body(q);let n=0;
  for(const i of(b.rows||[]).slice(0,5000)){const v=num(i.m);if(v){db.results.push({id:db.nid++,k:s.kid,m:v,t:+i.t||Date.now(),src:'import'});n++}}save();return send(r,200,{imported:n})}
 const mm=/^\/api\/results\/(\d+)$/.exec(p);
 if(mm){const x=mine.find(x=>x.id==mm[1]);if(!x)return send(r,404,{error:'Not found'});
  if(m==='PUT'){const v=num((await body(q)).m);if(!v)return send(r,400,{error:'Invalid multiplier'});x.m=v;save();return send(r,200,x)}
  if(m==='DELETE'){db.results=db.results.filter(y=>y!==x);save();return send(r,200,{ok:1})}}
 if(p.startsWith('/api/admin/')){
  if(!s.admin)return send(r,403,{error:'Admin only'});
  if(p==='/api/admin/keys'&&m==='GET')return send(r,200,db.keys.map(({id,label,active,admin,created})=>({id,label,active,admin,created,rounds:db.results.filter(x=>x.k===id).length})));
  if(p==='/api/admin/keys'&&m==='POST'){const b=await body(q);if(!b.key||String(b.key).length<8)return send(r,400,{error:'Key must be ≥ 8 chars'});addKey(b.key,b.label||'User',false);return send(r,200,{ok:1})}
  const km=/^\/api\/admin\/keys\/([\w-]+)$/.exec(p);
  if(km&&m==='PATCH'){const k=db.keys.find(k=>k.id===km[1]);if(!k||k.admin)return send(r,400,{error:'Cannot change this key'});k.active=!k.active;
   if(!k.active)for(const i in db.sessions)if(db.sessions[i].kid===k.id)delete db.sessions[i];save();return send(r,200,{active:k.active})}
  if(p==='/api/admin/sessions')return send(r,200,Object.values(db.sessions).map(({label,created,exp})=>({label,created,exp})));}
 send(r,404,{error:'Not found'});
 }catch(e){console.error(e);send(r,500,{error:'Server error'})}
}).listen(PORT,()=>console.log('http://localhost:'+PORT));
