const { spawn } = require('child_process');
const P=4471, B='http://localhost:'+P;
const env={...process.env,HCP_PORT:P,HCP_DB:'/tmp/tf/w.db',HCP_KEY:'/tmp/tf/k.json',HCP_STATE:'/tmp/tf/s.json',HCP_URL:B};
require('fs').rmSync('/tmp/tf',{recursive:true,force:true}); require('fs').mkdirSync('/tmp/tf');
const w=spawn('node',['server.js'],{env,cwd:__dirname}); let log=''; w.stdout.on('data',d=>log+=d); w.stderr.on('data',d=>log+=d);
const post=(b)=>fetch(B+'/announce',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(b)}).then(r=>r.status);
const hex=i=>i.toString(16).padStart(64,'0');
(async()=>{
 await new Promise(r=>setTimeout(r,2500));
 let s=[];
 // 1000 announcers on one domain
 for(let i=0;i<1000;i++) s.push(await post({url:'https://n'+i+'.evil.net',pubkey:hex(i+1),version:'x'}));
 // one announcer pushing 50 duckdns names, repeated from 40 announcers on distinct domains
 for(let k=0;k<40;k++){ const peers=[...Array(50)].map((_,i)=>({url:'https://e'+(k*50+i)+'.duckdns.org',pubkey:hex(50000+k*50+i)}));
   await post({url:'https://honest'+k+'.org',pubkey:hex(90000+k),version:'x',peers}); }
 // 300 distinct domains
 for(let i=0;i<300;i++) await post({url:'https://site'+i+'.com',pubkey:hex(70000+i),version:'x'});
 const r=await (await fetch(B+'/peers')).json();
 const urls=r.peers.map(p=>p.url);
 const c=f=>urls.filter(f).length;
 console.log('total peers',urls.length,'| evil.net',c(u=>u.includes('evil.net')),'| duckdns',c(u=>u.includes('duckdns')),'| honest',c(u=>/honest\d+\.org/.test(u)),'| site*.com',c(u=>/site\d+\.com/.test(u)));
 console.log('statuses for evil.net: 200s',s.filter(x=>x==200).length,'429s',s.filter(x=>x==429).length);
 // known peer refresh still works
 console.log('refresh known evil peer:', await post({url:'https://n0.evil.net',pubkey:hex(1),version:'y'}));
 w.kill();
})();
