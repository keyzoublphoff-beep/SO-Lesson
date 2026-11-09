import { getStore } from '@netlify/blobs';
import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
import keyBank from './answer-keys.json' with { type: 'json' };
const users = () => getStore('so-lesson-users-v1');
const sessions = () => getStore('so-lesson-sessions-v1');
const json = (body,status=200) => new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store','Access-Control-Allow-Origin':'same-origin'}});
const digest = value => createHash('sha256').update(value).digest('hex');
const hashCode = (pin,salt)=>scryptSync(pin,salt,64).toString('hex');
const validName = v => /^[A-Za-z0-9_-]{3,24}$/.test(v||'');
const publicName = x => x.replace(/[^A-Za-z0-9_-]/g,'').slice(0,24);

async function authenticated(req){
 const token=(req.headers.get('Authorization')||'').replace(/^Bearer /,'');
 if(!/^[a-f0-9]{64}$/.test(token))return null;
 const session=await sessions().get(digest(token),{type:'json'});
 if(!session||session.expires<Date.now())return null;
 return session.user;
}
export default async (req) => {
 if(req.method!=='POST')return json({error:'Méthode non autorisée'},405);
 let body;try {body=await req.json()}catch{return json({error:'Requête invalide'},400)}
 const {action}=body||{};
 try{
  if(action==='signup'||action==='login'){
   const username=String(body.username||'').trim(), name=username.toLowerCase(), pin=String(body.pin||'');
   if(!validName(username)||pin.length<(action==='signup'?12:6)||pin.length>128)return json({error:'Pseudo : 3 à 24 lettres/chiffres/_/-. Nouveaux comptes : mot de passe de 12 caractères minimum.'},400);
   const store=users();let user=await store.get(name,{type:'json'});
   if(action==='signup'){
    if(user)return json({error:'Pseudo déjà utilisé.'},409);
    const salt=randomBytes(16).toString('hex');
    user={username:publicName(username),salt,hash:hashCode(pin,salt),points:{},solved:{},failed:0,lockUntil:0,createdAt:Date.now()};
    // onlyIfNew protects against concurrent duplicate signups.
    const saved=await store.setJSON(name,user,{onlyIfNew:true});
    if(saved?.modified===false)return json({error:'Pseudo déjà utilisé.'},409);
   }else{
    if(!user)return json({error:'Identifiants invalides.'},401);
    if(user.lockUntil>Date.now())return json({error:'Trop de tentatives. Réessaie dans 10 minutes.'},429);
    const expected=Buffer.from(user.hash,'hex'), actual=Buffer.from(hashCode(pin,user.salt),'hex');
    if(!timingSafeEqual(expected,actual)){
     const failed=(user.failed||0)+1;
     await store.setJSON(name,{...user,failed:failed>=5?0:failed,lockUntil:failed>=5?Date.now()+10*60*1000:0});
     return json({error:'Identifiants invalides.'},401);
    }
    if(user.failed||user.lockUntil)await store.setJSON(name,{...user,failed:0,lockUntil:0});
   }
   const token=randomBytes(32).toString('hex');
   await sessions().setJSON(digest(token),{user:name,expires:Date.now()+14*24*3600*1000});
   return json({username:user.username,token});
  }
  if(action==='me'){
   const name=await authenticated(req);if(!name)return json({error:'Session expirée.'},401);
   const user=await users().get(name,{type:'json'});if(!user)return json({error:'Compte introuvable.'},404);
   return json({username:user.username,points:user.points||{}});
  }
  if(action==='score'){
   const name=await authenticated(req);if(!name)return json({error:'Connecte-toi pour enregistrer les points.'},401);
   const subject=String(body.subject||''), answers=body.answers;
   if(!Object.hasOwn(keyBank,subject)||!Array.isArray(answers)||answers.length<1||answers.length>200)return json({error:'Test non valide.'},400);
   const seen=new Set(), newlyCorrect=[];let good=0;
   for(const a of answers){
    if(!a||!Number.isInteger(a.id)||a.id<0||a.id>=keyBank[subject].length||!Number.isInteger(a.choice)||a.choice<0||a.choice>5||seen.has(a.id))return json({error:'Réponses non valides.'},400);
    seen.add(a.id);
    if(keyBank[subject][a.id]===a.choice){good++;newlyCorrect.push(a.id)}
   }
   const store=users();const user=await store.get(name,{type:'json'});if(!user)return json({error:'Compte introuvable.'},404);
   user.solved ??={};user.points ??={};const existing=new Set(user.solved[subject]||[]);
   let fresh=0;for(const id of newlyCorrect){if(!existing.has(id)){existing.add(id);fresh++}}
   user.solved[subject]=[...existing].sort((a,b)=>a-b);user.points[subject]=existing.size*10;
   await store.setJSON(name,user);
   const totalPoints=Object.values(user.points).reduce((a,b)=>a+Number(b||0),0);
   return json({good,total:answers.length,added:fresh*10,subjectPoints:user.points[subject],totalPoints});
  }
  if(action==='leaderboard'){
   const store=users(),{blobs}=await store.list();
   const list=await Promise.all(blobs.slice(0,500).map(entry=>store.get(entry.key,{type:'json'}).catch(()=>null)));
   const rows=list.filter(p=>p&&Object.keys(p.points||{}).length).map(p=>{
    const points=p.points||{},total=Object.values(points).reduce((a,b)=>a+Number(b||0),0);
    return {username:p.username,points,total};
   }).sort((a,b)=>b.total-a.total||a.username.localeCompare(b.username)).slice(0,50);
   return json({rows});
  }
  return json({error:'Action inconnue'},404);
 }catch(e){console.error('api-error',e);return json({error:'Erreur du serveur. Vérifie le déploiement et Netlify Blobs.'},500)}
};
