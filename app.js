import { analyse, summary, permissionRows, normaliseRoot, RULES, STORE_RULES, CWS_SOURCE, CWS_PAGE_UPDATED, RULES_VERIFIED } from './analyser.js';

const ORDER_EMAIL = 'info@ecobubble.it';
const ORDER_SUBJECT = 'Order: Chrome Extension Compliance Pack (EUR 29)';
const ORDER_BODY = `Hello,

I would like to buy the Chrome Extension Compliance Pack (EUR 29).

Name or company:
Country:
VAT number (businesses only):
Billing address:

EU consumers only: I request immediate delivery of the digital content and acknowledge that I lose my 14-day right of withdrawal once delivery starts (yes/no):
`;
const $ = (s)=>document.querySelector(s);
let state = {name:'', version:'', manifest:null, files:{}, results:[], nested:''};
const stores=()=>['chrome',...['firefox','edge'].filter(x=>document.querySelector(`#store-${x}`)?.checked)];
const ruleCount=()=>RULES.length+STORE_RULES.filter(r=>stores().includes(r.store)).length;

async function inflate(bytes) { if (!bytes.length) return new Uint8Array(); const ds=new DecompressionStream('deflate-raw'); const stream=new Blob([bytes]).stream().pipeThrough(ds); return new Uint8Array(await new Response(stream).arrayBuffer()); }
function u16(a,o){return a[o]|a[o+1]<<8} function u32(a,o){return (a[o]|a[o+1]<<8|a[o+2]<<16|a[o+3]<<24)>>>0;}
async function readZip(file) {
  const a=new Uint8Array(await file.arrayBuffer()); const files={}; let eocd=-1;
  for(let i=a.length-22;i>=0;i--){if(u32(a,i)===0x06054b50){eocd=i;break;}}
  if(eocd<0) throw new Error('The selected file is not a readable ZIP archive.');
  let count=u16(a,eocd+10), pos=u32(a,eocd+16);
  for(let n=0;n<count;n++){
    if(u32(a,pos)!==0x02014b50) throw new Error('ZIP central directory is malformed.');
    const method=u16(a,pos+10), csize=u32(a,pos+20), nsize=u32(a,pos+24), nl=u16(a,pos+28), el=u16(a,pos+30), cl=u16(a,pos+32), local=u32(a,pos+42);
    const name=new TextDecoder().decode(a.slice(pos+46,pos+46+nl)); pos+=46+nl+el+cl; if(name.endsWith('/')||name.startsWith('__MACOSX/')) continue;
    if(u32(a,local)!==0x04034b50) continue; const lnl=u16(a,local+26), lel=u16(a,local+28); const compressed=a.slice(local+30+lnl+lel,local+30+lnl+lel+csize); let data;
    if(method===0)data=compressed; else if(method===8)data=await inflate(compressed); else throw new Error(`Unsupported ZIP compression for ${name}.`);
    if(data.length!==nsize) throw new Error(`ZIP entry size mismatch for ${name}.`);
    files[name]=new TextDecoder().decode(data);
  }
  return files;
}
function escape(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function badge(r){return r.cws?`<a class="cws" href="${r.cwsUrl}" target="_blank" rel="noopener">${escape(r.cws)}</a>`:'';}
function reportData(){return {generatedAt:new Date().toLocaleString(),...state,summary:summary(state.results),permissions:permissionRows(state.manifest||{})};}
function render(){const s=summary(state.results); $('#summary').innerHTML=`<span class="pill pass">${s.pass} pass</span><span class="pill warning">${s.warning} warning</span><span class="pill error">${s.error} error</span>`; $('#manifest-name').textContent=state.name||'No extension loaded'; $('#manifest-meta').textContent=state.version?`Manifest V3 · version ${state.version}`:'Choose a ZIP to begin'; $('#results').innerHTML=state.results.map(r=>`<article class="result ${r.status}"><div><span class="status">${r.status}</span><strong>${escape(r.title)}</strong>${badge(r)}<p>${escape(r.message)}</p>${r.files?.length?`<small>${r.files.map(escape).join(', ')}</small>`:''}</div><aside>${escape(r.remediation)}</aside></article>`).join(''); $('#permissions').innerHTML=state.manifest?permissionRows(state.manifest).map(p=>`<tr><td><code>${escape(p.permission)}</code></td><td>${escape(p.kind)}</td><td>${escape(p.why)}</td></tr>`).join(''):'<tr><td colspan="3">Load a ZIP to generate permission prompts.</td></tr>'; $('#results-card').hidden=!state.results.length;}
const code=(r)=>r.cws?` [${r.cws}]`:'';
function markdown(d){return `# Chrome Extension Compliance Report\n\nGenerated locally: ${d.generatedAt}\nRules verified against ${CWS_SOURCE} (page updated ${CWS_PAGE_UPDATED}) on ${RULES_VERIFIED}.\n\n## Summary\n\n- Extension: ${d.name||'Unknown'}\n- Version: ${d.version||'Unknown'}\n- Pass: ${d.summary.pass}\n- Warning: ${d.summary.warning}\n- Error: ${d.summary.error}\n\n## Findings\n\n${d.results.map(r=>`### ${r.status.toUpperCase()}: ${r.title}${code(r)}\n${r.message}\n\nRemediation: ${r.remediation}\nFiles: ${(r.files||[]).join(', ')||'n/a'}${r.cwsUrl?`\nPolicy: ${r.cwsUrl}`:''}\n`).join('\n')}\n## Permission justification prompts\n\n${d.permissions.map(p=>`- **${p.permission}** (${p.kind}): ${p.why}`).join('\n')||'No permissions declared.'}\n\n> Preparation aid only. Not legal advice, malware scanning, or a Chrome Web Store approval guarantee.\n`;}
function html(d){return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Compliance report: ${escape(d.name)}</title><style>body{font:16px system-ui;max-width:920px;margin:32px auto;padding:0 20px;color:#17202a}h1{margin-bottom:4px}.grid{display:flex;gap:10px;flex-wrap:wrap}.pill{padding:8px 12px;border-radius:99px}.pass{color:#176b49;background:#e1f5ea}.warning{color:#8a5800;background:#fff2c9}.error{color:#a12;background:#ffe1e1}article{border:1px solid #ddd;border-left:5px solid;padding:12px;margin:10px 0}article.pass{border-left-color:#2b9b69}article.warning{border-left-color:#d69b1a}article.error{border-left-color:#c34242}aside,small{font-size:.9em;color:#555}</style></head><body><h1>${escape(d.name||'Extension')}</h1><p>Version ${escape(d.version||'unknown')} · Generated locally ${escape(d.generatedAt)}<br><small>Rules verified against the Chrome Web Store troubleshooting page (updated ${CWS_PAGE_UPDATED}) on ${RULES_VERIFIED}.</small></p><div class="grid"><span class="pill pass">${d.summary.pass} pass</span><span class="pill warning">${d.summary.warning} warning</span><span class="pill error">${d.summary.error} error</span></div>${d.results.map(r=>`<article class="${r.status}"><strong>${r.status.toUpperCase()}: ${escape(r.title)}${escape(code(r))}</strong><p>${escape(r.message)}</p><small>Remediation: ${escape(r.remediation)} · Files: ${escape((r.files||[]).join(', ')||'n/a')}${r.cwsUrl?` · <a href="${r.cwsUrl}">policy</a>`:''}</small></article>`).join('')}<h2>Permission prompts</h2><ul>${d.permissions.map(p=>`<li><code>${escape(p.permission)}</code>: ${escape(p.why)}</li>`).join('')||'<li>No permissions declared.</li>'}</ul><p><em>Preparation aid only. Not legal advice, malware scanning, or an approval guarantee.</em></p></body></html>`;}
function download(name,type,body){const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([body],{type}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
async function load(file){try{if(!file||!file.name.toLowerCase().endsWith('.zip'))throw new Error('Please choose a .zip file.');const {files,nested}=normaliseRoot(await readZip(file));if(!files['manifest.json'])throw new Error('This ZIP does not contain manifest.json at its root.');let manifest;try{manifest=JSON.parse(files['manifest.json']);}catch{throw new Error('manifest.json is not valid JSON.');}state={name:manifest.name||file.name,version:manifest.version||'',manifest,files,nested,results:analyse(manifest,files,{nested,stores:stores()})};$('#notice').textContent='Analysis complete. ZIP contents stayed in this browser tab.';render();}catch(e){state={name:'',version:'',manifest:null,files:{},results:[],nested:''};render();$('#notice').textContent=e.message;}}
$('#zip').addEventListener('change',e=>load(e.target.files[0])); $('#demo').addEventListener('click',async()=>{const r=await fetch('./fixtures/sample-extension.zip');load(new File([await r.blob()],'sample-extension.zip',{type:'application/zip'}));}); $('#demo-bad').addEventListener('click',async()=>{const r=await fetch('./fixtures/rejected-extension.zip');load(new File([await r.blob()],'rejected-extension.zip',{type:'application/zip'}));}); $('#export-md').addEventListener('click',()=>download('chrome-compliance-report.md','text/markdown',markdown(reportData()))); $('#export-html').addEventListener('click',()=>download('chrome-compliance-report.html','text/html',html(reportData())));
const order=`mailto:${ORDER_EMAIL}?subject=${encodeURIComponent(ORDER_SUBJECT)}&body=${encodeURIComponent(ORDER_BODY)}`; document.querySelectorAll('[data-order]').forEach(a=>a.href=order);
const recount=()=>{$('#rule-count').textContent=ruleCount();}; recount();
document.querySelectorAll('.stores input').forEach(i=>i.addEventListener('change',()=>{recount(); if(state.manifest){state.results=analyse(state.manifest,state.files,{nested:state.nested,stores:stores()}); render();}})); $('#rules-meta').innerHTML=`Rules verified on ${RULES_VERIFIED} against the <a href="${CWS_SOURCE}" target="_blank" rel="noopener">Chrome Web Store troubleshooting page</a> (page updated ${CWS_PAGE_UPDATED}).`;
render();
