'use strict';
const issuer = 'http://localhost:8180/realms/biolims';
const callback = 'http://localhost:8080/callback.html';
const key = 'biolims_oauth';
const random = n => {const b=new Uint8Array(n);crypto.getRandomValues(b);return b64(b)};
const b64 = b => btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const show = v => {const node=document.getElementById('result'); if(node)node.textContent=typeof v==='string'?v:JSON.stringify(v,null,2)};
async function login(){
 const verifier=random(32), state=random(24);
 const challenge=b64(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(verifier))));
 sessionStorage.setItem(key,JSON.stringify({verifier,state}));
 const scopes=document.getElementById('scope').value.trim().split(/\s+/).filter(Boolean);
 const allowed=['orders.read','orders.write','assays.read','assays.run','reports.read'];
 if(scopes.some(x=>!allowed.includes(x))){show('Невідомий scope');return}
 const params=new URLSearchParams({client_id:'biolims-web',redirect_uri:callback,response_type:'code',scope:['openid',...scopes].join(' '),state,code_challenge:challenge,code_challenge_method:'S256'});
 location.href=issuer+'/protocol/openid-connect/auth?'+params;
}
async function finish(){
 const url=new URL(location.href),code=url.searchParams.get('code'),state=url.searchParams.get('state');
 const saved=JSON.parse(sessionStorage.getItem(key)||'null');
 // Remove the one-time state and the code from the address before exchanging it.
 sessionStorage.removeItem(key);history.replaceState({},'',location.pathname);
 if(!saved||!state||state!==saved.state||!code)throw Error('Не вдалося перевірити state або отримати code');
 const body=new URLSearchParams({grant_type:'authorization_code',client_id:'biolims-web',redirect_uri:callback,code,code_verifier:saved.verifier});
 const r=await fetch(issuer+'/protocol/openid-connect/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
 const data=await r.json();if(!r.ok||!data.access_token)throw Error('Помилка отримання токена: '+(data.error||r.status));
 sessionStorage.setItem('biolims_token',data.access_token);sessionStorage.setItem('biolims_scope',data.scope||'');
 location.replace('/');
}
async function call(path,method='GET',body){
 const token=sessionStorage.getItem('biolims_token');
 const headers={};if(token)headers.Authorization='Bearer '+token;if(body)headers['Content-Type']='application/json';
 try{const res=await fetch(path,{method,headers,body:body?JSON.stringify(body):undefined});let data=await res.text();try{data=JSON.parse(data)}catch{}show({http_status:res.status,data});}catch(e){show('Помилка: '+e.message)}
}
if(location.pathname==='/callback.html') finish().catch(e=>{document.getElementById('state').textContent=e.message});
else {
 document.getElementById('state').textContent=sessionStorage.getItem('biolims_token')?'Вхід виконано. Scopes: '+sessionStorage.getItem('biolims_scope'):'Не виконано вхід';
 document.getElementById('login').onclick=()=>login().catch(e=>show(e.message));
 document.getElementById('logout').onclick=()=>{sessionStorage.clear();location.reload()};
 document.querySelectorAll('[data-path]').forEach(button=>button.onclick=()=>call(button.dataset.path+encodeURIComponent(document.getElementById('barcode').value)));
 document.getElementById('assay').onclick=()=>call('/api/assays/run','POST',{barcode:document.getElementById('barcode').value,simulate_failure:false});
}
