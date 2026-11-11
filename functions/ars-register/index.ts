// Public signup endpoint. Secret credentials stay inside Supabase Edge Functions.
const projectUrl = Deno.env.get('SUPABASE_URL')!;
const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const origins = new Set(['https://gyumri-demo-ars-elite-cakes.onrender.com','http://127.0.0.1:4173','http://terminal.local:4173']);
Deno.serve(async (req: Request) => {
 const origin=req.headers.get('origin')||'';
 const headers={'Content-Type':'application/json','Access-Control-Allow-Origin':origins.has(origin)?origin:'https://gyumri-demo-ars-elite-cakes.onrender.com','Access-Control-Allow-Headers':'authorization, apikey, content-type, x-client-info','Access-Control-Allow-Methods':'POST, OPTIONS','Vary':'Origin'};
 const reply=(body:unknown,status=200)=>new Response(JSON.stringify(body),{status,headers});
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return reply({error:'Method not allowed'},405);
 if(origin&&!origins.has(origin))return reply({error:'Origin not allowed'},403);
 try {
  if(Number(req.headers.get('content-length')||0)>5000)return reply({error:'Request too large'},413);
  const text=await req.text();if(text.length>5000)return reply({error:'Request too large'},413);
  const {email,password,full_name,phone}=JSON.parse(text);
  if(typeof email!=='string'||email.length>254||!/^\S+@\S+\.\S+$/.test(email)||typeof password!=='string'||password.length<10||password.length>128||typeof full_name!=='string'||!full_name.trim()||full_name.length>100||typeof phone!=='string'||phone.length>40)return reply({error:'Invalid registration details'},400);
  const ip=req.headers.get('x-forwarded-for')?.split(',')[0].trim()||req.headers.get('cf-connecting-ip')||'unknown';
  const hash=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(ip));
  const key=Array.from(new Uint8Array(hash)).map(x=>x.toString(16).padStart(2,'0')).join('');
  const h={apikey:serviceKey,Authorization:`Bearer ${serviceKey}`,'Content-Type':'application/json'};
  const limited=await fetch(`${projectUrl}/rest/v1/rpc/signup_rate_limit`,{method:'POST',headers:h,body:JSON.stringify({p_key:key})});
  if(!limited.ok||await limited.json()!==true)return reply({error:'Too many registrations. Please try later.'},429);
  const response=await fetch(`${projectUrl}/auth/v1/admin/users`,{method:'POST',headers:h,body:JSON.stringify({email:email.trim().toLowerCase(),password,email_confirm:true,user_metadata:{full_name:full_name.trim(),phone}})});
  if(!response.ok)return reply({error:'Unable to register. If you already have an account, sign in.'},400);
  const user=await response.json();
  const profile=await fetch(`${projectUrl}/rest/v1/profiles`,{method:'POST',headers:{...h,Prefer:'resolution=merge-duplicates'},body:JSON.stringify({user_id:user.id,full_name:full_name.trim(),phone})});
  if(!profile.ok)return reply({error:'Account created. Please sign in and complete your profile.'},200);
  return reply({ok:true});
 }catch{return reply({error:'Registration unavailable. Please try again.'},500)}
});
