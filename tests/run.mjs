import puppeteer from 'puppeteer-core';
import fs from 'fs';
const out='/tmp/shots70';fs.mkdirSync(out,{recursive:true});
const browser=await puppeteer.launch({executablePath:'/usr/bin/google-chrome',headless:'new',args:['--no-sandbox','--disable-dev-shm-usage','--hide-scrollbars']});
let fails=[];
const check=(name,ok,extra='')=>{console.log((ok?'PASS':'FAIL')+' '+name+(extra?' — '+extra:''));if(!ok)fails.push(name);};
for(const v of [{name:'desktop',w:1440,h:900},{name:'mobile',w:390,h:844}]){
 for(const theme of ['light','dark']){
  const page=await browser.newPage();
  await page.setViewport({width:v.w,height:v.h,deviceScaleFactor:1});
  const errs=[];page.on('pageerror',e=>errs.push(String(e)));page.on('console',m=>{if(m.type()==='error')errs.push(m.text());});
  await page.evaluateOnNewDocument(t=>localStorage.setItem('theme',t),theme);
  await page.goto('http://localhost:8070',{waitUntil:'networkidle2'});
  await new Promise(s=>setTimeout(s,1200));
  // seeded history
  const st0=await page.evaluate(()=>window._test.state());
  check(`${v.name}/${theme} seeded with history`,st0.events>=30,st0.events+' events');
  check(`${v.name}/${theme} severity variety`,st0.sevDist.filter(n=>n>0).length>=3,st0.sevDist.join(','));
  // feed table renders
  const rows=await page.$$eval('#tblFeed tbody tr',e=>e.length);
  check(`${v.name}/${theme} feed renders`,rows>=20,rows+' rows');
  // start the feed and watch it grow
  const before=await page.evaluate(()=>{document.getElementById('rateSel').value='500';return window._test.state().events;});
  await page.click('#btnStart');
  await new Promise(s=>setTimeout(s,3500));
  const after=await page.evaluate(()=>window._test.state());
  check(`${v.name}/${theme} live feed grows`,after.events>before+3,`${before} -> ${after.events}`);
  check(`${v.name}/${theme} running state`,after.running===true);
  await page.click('#btnStart'); // pause
  const paused=await page.evaluate(()=>window._test.state().running);
  check(`${v.name}/${theme} pause works`,paused===false);
  // severity filter
  await page.select('#fltSev','critical');
  await new Promise(s=>setTimeout(s,250));
  const critChips=await page.$$eval('#tblFeed tbody .chip',e=>e.map(x=>x.textContent));
  check(`${v.name}/${theme} severity filter`,critChips.length>0&&critChips.every(c=>c==='critical'),critChips.slice(0,3).join(','));
  // text filter
  await page.select('#fltSev','');
  await page.type('#fltQ','phishing');
  await new Promise(s=>setTimeout(s,400));
  const phRows=await page.$$eval('#tblFeed tbody tr',e=>e.map(x=>x.textContent));
  check(`${v.name}/${theme} text filter`,phRows.length>0&&phRows.every(r=>/Phishing/i.test(r)),phRows.length+' rows');
  await page.evaluate(()=>{document.getElementById('fltQ').value='';document.getElementById('fltQ').dispatchEvent(new Event('input'));});
  // sources table + charts present
  const srcRows=await page.$$eval('#tblSrc tbody tr',e=>e.length);
  check(`${v.name}/${theme} sources table`,srcRows>=4,srcRows+' sources');
  const canvases=await page.$$eval('canvas',e=>e.map(c=>c.width>0&&c.height>0));
  check(`${v.name}/${theme} charts rendered`,canvases.length===3&&canvases.every(Boolean));
  // honest limits visible
  const lim=await page.$eval('.limit-box',e=>e.textContent);
  check(`${v.name}/${theme} simulation disclaimer`,/simulated/i.test(lim));
  await page.evaluate(()=>window.scrollTo(0,0));
  await page.screenshot({path:`${out}/top-${v.name}-${theme}.png`});
  await page.evaluate(()=>document.getElementById('feed').scrollIntoView({block:'start'}));
  await new Promise(s=>setTimeout(s,250));
  await page.screenshot({path:`${out}/feed-${v.name}-${theme}.png`});
  check(`${v.name}/${theme} no console errors`,errs.length===0,errs.slice(0,3).join('|'));
  await page.close();
 }
}
await browser.close();
if(fails.length){console.log('\nFAILURES: '+fails.join(', '));process.exit(1);}
console.log('\nALL PASS');
