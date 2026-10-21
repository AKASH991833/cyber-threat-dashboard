/* Cyber Threat Dashboard - simulated SOC feed and analytics */
(function(){
'use strict';
const $=s=>document.querySelector(s);
const TYPES=[
 ['Brute force login',.18,'high'],['Port scan',.16,'low'],['SQL injection attempt',.10,'critical'],
 ['Phishing email detected',.12,'medium'],['Malware signature match',.06,'critical'],
 ['Anomalous data transfer',.08,'high'],['DNS tunneling pattern',.05,'high'],
 ['Failed MFA push',.12,'medium'],['Privilege escalation',.04,'critical'],
 ['Geo-impossible login',.05,'high'],['Rate limit tripped',.04,'low']
];
const NETWORKS=['185.220.101.x (TOR exit)','45.155.204.x (hosting)','103.86.96.x (residential)','91.240.118.x (hosting)','202.131.224.x (cloud)','77.91.85.x (VPN)','196.52.43.x (cloud)','194.26.192.x (hosting)'];
const TARGETS=['auth-gateway','web-frontend','mail-server','vpn-concentrator','db-replica','ci-runner'];
const SEVS=['low','medium','high','critical'];
const SEV_CLS={low:'chip-ok',medium:'chip-accent',high:'chip-warn',critical:'chip-bad'};

let events=[],running=false,timer=null,charts={};
function pick(a){return a[Math.floor(Math.random()*a.length)];}
function genEvent(){
  let r=Math.random(),type=TYPES[0];
  for(const t of TYPES){if(r<t[1]){type=t;break;}r-=t[1];}
  const [name,_,sev]=type;
  return {id:events.length+1,ts:Date.now(),type:name,sev,src:pick(NETWORKS),dst:pick(TARGETS),
    detail:`${name} from ${pick(NETWORKS).split(' ')[0]} against ${pick(TARGETS)} - auto-triaged by rule engine`};
}
function pushEvent(){
  const e=genEvent();e.detail=`${e.type} from ${e.src.split(' ')[0]} against ${e.dst} - auto-triaged by rule engine`;
  events.unshift(e);if(events.length>300)events.length=300;
  render();
}

function kpis(){
  const n=events.length;
  const crit=events.filter(e=>e.sev==='critical').length;
  const high=events.filter(e=>e.sev==='high').length;
  const lastMin=events.filter(e=>Date.now()-e.ts<60000).length;
  $('#kpis').innerHTML=[
    ['Events (session)',n],['Critical',crit],['High',high],['Last minute',lastMin]
  ].map(([l,v])=>`<div class="card kpi"><div class="small muted">${l}</div><div class="kpi-val">${v}</div></div>`).join('');
}
function feed(){
  const sev=$('#fltSev').value,q=$('#fltQ').value.toLowerCase();
  const list=events.filter(e=>(!sev||e.sev===sev)&&(!q||e.type.toLowerCase().includes(q)||e.src.toLowerCase().includes(q)||e.dst.includes(q))).slice(0,60);
  $('#feedMeta').textContent=running?`Live - ${events.length} events this session`:`Paused - ${events.length} events this session`;
  $('#tblFeed').innerHTML=`<thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Source</th><th>Target</th></tr></thead><tbody>`+
    list.map(e=>`<tr><td class="small muted">${new Date(e.ts).toLocaleTimeString()}</td><td>${esc(e.type)}</td><td><span class="chip ${SEV_CLS[e.sev]}">${e.sev}</span></td><td class="small">${esc(e.src)}</td><td class="small">${esc(e.dst)}</td></tr>`).join('')+'</tbody>';
}
function sources(){
  const cnt={};for(const e of events)cnt[e.src]=(cnt[e.src]||0)+1;
  const top=Object.entries(cnt).sort((a,b)=>b[1]-a[1]).slice(0,8);
  $('#tblSrc').innerHTML='<thead><tr><th>Source network</th><th>Events</th><th>Share</th></tr></thead><tbody>'+
    top.map(([s,n])=>`<tr><td class="small">${esc(s)}</td><td>${n}</td><td>${events.length?Math.round(n/events.length*100):0}%</td></tr>`).join('')+'</tbody>';
}
function chartTheme(){return {color:getComputedStyle(document.documentElement).getPropertyValue('--ink').trim()||'#0f172a'};}
function makeCharts(){
  const c=chartTheme();
  if(charts.time)charts.time.destroy();
  charts.time=new Chart($('#chTime'),{type:'line',data:{labels:[],datasets:SEVS.map(s=>({label:s,data:[],borderColor:{low:'#0e9f6e',medium:'#6366f1',high:'#d97706',critical:'#dc2626'}[s],tension:.3,pointRadius:0,borderWidth:2}))},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:c.color}}},scales:{x:{ticks:{color:c.color}},y:{ticks:{color:c.color},beginAtZero:true}}}});
  if(charts.sev)charts.sev.destroy();
  charts.sev=new Chart($('#chSev'),{type:'doughnut',data:{labels:SEVS,datasets:[{data:[0,0,0,0],backgroundColor:['#0e9f6e','#6366f1','#d97706','#dc2626']}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:c.color}}}}});
  if(charts.type)charts.type.destroy();
  charts.type=new Chart($('#chType'),{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#b91c1c'}]},
    options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{ticks:{color:c.color}},y:{ticks:{color:c.color}}}}});
}
function updateCharts(){
  if(!charts.time)return;
  // per-minute buckets, last 10
  const buckets={};
  const now=Date.now();
  for(let i=9;i>=0;i--){const d=new Date(now-i*60000);buckets[d.getHours()+':'+String(d.getMinutes()).padStart(2,'0')]={low:0,medium:0,high:0,critical:0};}
  for(const e of events){const d=new Date(e.ts);const k=d.getHours()+':'+String(d.getMinutes()).padStart(2,'0');if(buckets[k])buckets[k][e.sev]++;}
  const labels=Object.keys(buckets);
  charts.time.data.labels=labels;
  charts.time.data.datasets.forEach((ds,i)=>ds.data=labels.map(l=>buckets[l][SEVS[i]]));
  charts.time.update('none');
  charts.sev.data.datasets[0].data=SEVS.map(s=>events.filter(e=>e.sev===s).length);
  charts.sev.update('none');
  const cnt={};for(const e of events)cnt[e.type]=(cnt[e.type]||0)+1;
  const top=Object.entries(cnt).sort((a,b)=>b[1]-a[1]).slice(0,6);
  charts.type.data.labels=top.map(t=>t[0]);charts.type.data.datasets[0].data=top.map(t=>t[1]);
  charts.type.update('none');
}
let renderQueued=false;
function render(){
  kpis();feed();
  if(!renderQueued){renderQueued=true;setTimeout(()=>{renderQueued=false;sources();updateCharts();},800);}
}
function setRunning(on){
  running=on;
  $('#btnStart').textContent=on?'Pause the feed':'Start the feed';
  clearInterval(timer);
  if(on){timer=setInterval(pushEvent,+$('#rateSel').value);}
  feed();
}
$('#btnStart').addEventListener('click',()=>setRunning(!running));
$('#rateSel').addEventListener('change',()=>{if(running)setRunning(true);});
$('#fltSev').addEventListener('change',feed);
$('#fltQ').addEventListener('input',debounce(feed,150));
$('#btnExport').addEventListener('click',()=>{download('threat-events.json',JSON.stringify(events,null,2),'application/json');toast('Events exported');});
document.addEventListener('themechange',()=>{makeCharts();updateCharts();});

makeCharts();
// seed a few minutes of history so the dashboard is not empty
const back=36;for(let i=back;i>0;i--){const e=genEvent();e.ts=Date.now()-i*15000;events.unshift(e);}
render();

window._test={gen:()=>{pushEvent();return events.length;},
  setRate:ms=>{$('#rateSel').value=String(ms);},
  state:()=>({events:events.length,critical:events.filter(e=>e.sev==='critical').length,running,types:[...new Set(events.map(e=>e.type))].length,sevDist:SEVS.map(s=>events.filter(e=>e.sev===s).length)})};
})();
