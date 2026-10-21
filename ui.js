/* Shared UI helpers: theme, nav, toast, utils */
(function(){
  const root=document.documentElement;
  const stored=localStorage.getItem('theme');
  const prefers=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches;
  root.setAttribute('data-theme', stored||(prefers?'dark':'light'));
  function applyMeta(){
    const m=document.querySelector('meta[name="theme-color"]');
    if(m) m.setAttribute('content', root.getAttribute('data-theme')==='dark'?'#0a1128':'#ffffff');
  }
  applyMeta();
  window.toggleTheme=function(){
    const next=root.getAttribute('data-theme')==='dark'?'light':'dark';
    root.setAttribute('data-theme',next);localStorage.setItem('theme',next);applyMeta();
    document.dispatchEvent(new CustomEvent('themechange',{detail:next}));
  };
  document.addEventListener('DOMContentLoaded',()=>{
    const mb=document.querySelector('.menu-btn'), nav=document.querySelector('.site-nav');
    if(mb&&nav){mb.addEventListener('click',()=>nav.classList.toggle('open'));
      nav.addEventListener('click',e=>{if(e.target.closest('a'))nav.classList.remove('open');});}
    document.querySelectorAll('[data-theme-toggle]').forEach(b=>b.addEventListener('click',window.toggleTheme));
    if('serviceWorker' in navigator && location.protocol.startsWith('http')){
      navigator.serviceWorker.register('sw.js').catch(()=>{});
    }
  });
  window.toast=function(msg){
    let z=document.querySelector('.toast-zone');
    if(!z){z=document.createElement('div');z.className='toast-zone';document.body.appendChild(z);}
    const t=document.createElement('div');t.className='toast';t.textContent=msg;z.appendChild(t);
    setTimeout(()=>{t.style.opacity='0';t.style.transition='opacity .3s';setTimeout(()=>t.remove(),320);},2600);
  };
  window.esc=function(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));};
  window.fmtNum=function(n,d=0){if(n==null||isNaN(n))return '—';return Number(n).toLocaleString('en-US',{minimumFractionDigits:d,maximumFractionDigits:d});};
  window.fmtMoney=function(n,d=2){if(n==null||isNaN(n))return '—';return Number(n).toLocaleString('en-US',{style:'currency',currency:'USD',minimumFractionDigits:d,maximumFractionDigits:d});};
  window.fmtPct=function(n,d=1){if(n==null||isNaN(n))return '—';return (n*100).toFixed(d)+'%';};
  window.download=function(name,content,type='text/plain'){
    const blob=content instanceof Blob?content:new Blob([content],{type});
    const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();
    setTimeout(()=>URL.revokeObjectURL(a.href),4000);
  };
  window.copyText=function(t,msg='Copied to clipboard'){navigator.clipboard.writeText(t).then(()=>toast(msg)).catch(()=>toast('Copy failed'));};
  window.debounce=function(f,ms){let h;return(...a)=>{clearTimeout(h);h=setTimeout(()=>f(...a),ms);};};
  window.parseCSV=function(text){
    const rows=[];let cur=[''],inQ=false,f='';
    for(let i=0;i<text.length;i++){const c=text[i];
      if(inQ){if(c==='"'){if(text[i+1]==='"'){f+='"';i++;}else inQ=false;}else f+=c;}
      else if(c==='"'){inQ=true;}
      else if(c===','){cur.push(f);f='';}
      else if(c==='\n'||c==='\r'){if(c==='\r'&&text[i+1]==='\n')i++;cur.push(f);rows.push(cur);cur=[''];f='';}
      else f+=c;}
    if(f!==''||cur.length>1){cur.push(f);rows.push(cur);}
    return rows.filter(r=>r.some(x=>String(x).trim()!==''));
  };
  window.toCSV=function(rows){return rows.map(r=>r.map(c=>{c=String(c??'');return /[",\n]/.test(c)?'"'+c.replace(/"/g,'""')+'"':c;}).join(',')).join('\n');};
})();
