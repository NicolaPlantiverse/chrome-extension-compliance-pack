import assert from 'node:assert/strict';
import { analyse, summary, permissionRows, normaliseRoot, RULES, ALL_RULES, STORE_RULES, cwsLink } from '../analyser.js';
const ALL = {stores:['chrome','firefox','edge']};

const st = (r, id) => r.find(x => x.id === id).status;

// Clean fixture: every rule passes or stays informational.
const good={manifest_version:3,name:'Safe Fixture',version:'1.0.0',description:'A harmless local fixture.',permissions:['storage','alarms'],host_permissions:[],action:{default_popup:'popup.html'},icons:{128:'icon-128.png'},background:{service_worker:'background.js'},content_security_policy:{extension_pages:"script-src 'self'; object-src 'self'"}};
const files={'manifest.json':JSON.stringify(good),'popup.html':'<h1>Safe fixture</h1><script src="popup.js"></script>','popup.js':'chrome.storage.local.get("k");','background.js':'chrome.alarms.create("tick",{periodInMinutes:5}); fetch("https://api.example.com/v1");','icon-128.png':'synthetic'};
let ok=analyse(good,files);
for (const id of ['zip-root','manifest-version','remote-code','icon-paths','html-paths','permissions-unused','permissions-misunderstood','insecure-endpoints','obfuscation','privacy-policy']) assert.equal(st(ok,id),'pass',`good fixture passes ${id}`);
assert.equal(summary(ok).error,0);

// Broken fixture: covers the original rules.
const bad={manifest_version:2,name:'Bad',version:'x',permissions:['tabs','webRequest'],host_permissions:['http://*/*','<all_urls>'],content_scripts:[{matches:['<all_urls>'],js:['missing.js']}],action:{default_popup:'missing.html'},icons:{128:'missing.png'},background:{service_worker:'remote.js'}};
let r=analyse(bad,{'manifest.json':JSON.stringify(bad),'page.js':'const x="https://cdn.example.com/a.js"; eval(x);'});
assert.ok(summary(r).error>=7);
for (const id of ['host-https','remote-code','content-script-js','icon-paths','manifest-version']) assert.equal(st(r,id),'error',`bad fixture fails ${id}`);
assert.equal(st(r,'permissions-unused'),'warning'); assert.match(r.find(x=>x.id==='permissions-unused').message,/tabs, webRequest/);
assert.match(r.find(x=>x.id==='permissions-misunderstood').message,/tabs is redundant with broad host access/);
assert.equal(st(r,'privacy-policy'),'warning');
assert.ok(permissionRows(bad).length===4);

// Purple Potassium: misunderstood permissions documented on the official page.
const mis={manifest_version:3,name:'M',version:'1.0',permissions:['activeTab','tabs','cookies','storage'],host_permissions:['https://*/*']};
r=analyse(mis,{'manifest.json':'{}','bg.js':'chrome.tabs.query({}); document.cookie; localStorage.setItem("a","b");'});
const msg=r.find(x=>x.id==='permissions-misunderstood').message;
for (const s of ['activeTab is redundant','tabs is redundant','cookies is not needed','storage is not needed']) assert.ok(msg.includes(s),s);
r=analyse({...mis,host_permissions:[],permissions:['tabs']},{'bg.js':'chrome.tabs.create({});'});
assert.match(r.find(x=>x.id==='permissions-misunderstood').message,/only needed to read url/);
r=analyse({...mis,host_permissions:[],permissions:['tabs']},{'bg.js':'chrome.tabs.query({}).then(t=>t[0].url);'});
assert.equal(st(r,'permissions-misunderstood'),'pass');

// Manifest-only use of a permission is not reported as unused.
r=analyse({manifest_version:3,name:'D',version:'1',permissions:['declarativeNetRequest'],declarative_net_request:{rule_resources:[{id:'r',enabled:true,path:'rules.json'}]}},{'rules.json':'[]'});
assert.equal(st(r,'permissions-unused'),'pass');
r=analyse({manifest_version:3,name:'G',version:'1',permissions:['geolocation','clipboardWrite']},{'a.js':'navigator.geolocation.getCurrentPosition(f); navigator.clipboard.writeText("x");'});
assert.equal(st(r,'permissions-unused'),'pass');

// Purple Copper: plain HTTP endpoints in network calls, localhost allowed.
r=analyse(good,{...files,'net.js':'fetch("http://tracker.example.com/c"); new WebSocket("ws://live.example.com"); fetch("http://localhost:8080/dev");'});
assert.equal(st(r,'insecure-endpoints'),'warning'); assert.doesNotMatch(r.find(x=>x.id==='insecure-endpoints').message,/localhost/);
r=analyse(good,{...files,'xhr.js':'x.open("POST","http://collect.example.com/p");'});
assert.equal(st(r,'insecure-endpoints'),'warning');

// Red Titanium: obfuscator output and encoded payloads flagged, plain minified code not.
const obf=Array.from({length:12},(_,i)=>`var _0x${(0xa1b2+i).toString(16)}=_0x${(0xa1b2+i).toString(16)}+1;`).join('');
r=analyse(good,{...files,'o.js':obf}); assert.equal(st(r,'obfuscation'),'warning');
r=analyse(good,{...files,'e.js':'eval(atob("Y29uc29sZS5sb2coMSk="));'}); assert.equal(st(r,'obfuscation'),'warning');
r=analyse(good,{...files,'m.js':'!function(n){var t=n.a,e=n.b;return t+e}({a:1,b:2});'.repeat(50)}); assert.equal(st(r,'obfuscation'),'pass');
assert.equal(st(analyse(good,{...files,'r.js':'function retrieval(){}; retrieval();'}),'remote-code'),'pass','eval word boundary');

// Yellow Magnesium: ZIP with a top folder.
const nested=normaliseRoot({'ext/manifest.json':JSON.stringify(good),'ext/popup.html':'x'});
assert.equal(nested.nested,'ext/'); assert.ok(nested.files['manifest.json']);
assert.equal(st(analyse(good,nested.files,{nested:nested.nested}),'zip-root'),'error');

// Firefox (AMO) and Edge rules, only when those stores are selected.
assert.equal(analyse(good,files).find(x=>x.store==='firefox'),undefined,'Chrome-only run has no Firefox rules');
r=analyse(good,files,ALL);
for (const id of ['ff-gecko-id','ff-data-collection','ff-background']) assert.equal(st(r,id),'error',`Chrome-only manifest fails ${id}`);
const ff={...good,background:{service_worker:'background.js',scripts:['background.js']},browser_specific_settings:{gecko:{id:'fixture@example.com',data_collection_permissions:{required:['none']}}}};
r=analyse(ff,files,ALL); for (const id of ['ff-gecko-id','ff-data-collection','ff-background','ff-source-code','edge-other-browser']) assert.equal(st(r,id),'pass',`Firefox-ready manifest passes ${id}`);
r=analyse({...ff,browser_specific_settings:{gecko:{id:'x@y',data_collection_permissions:{required:['technicalAndInteraction','emails'],optional:['none']}}}},files,ALL);
assert.match(r.find(x=>x.id==='ff-data-collection').message,/unknown value "emails".*technicalAndInteraction must be optional.*"none" belongs in required/);
r=analyse(good,{...files,'bundle.js':'(()=>{var __webpack_require__={};})();'},ALL); assert.equal(st(r,'ff-source-code'),'warning');
r=analyse({...good,name:'Price Helper for Chrome',description:'The best Google Chrome helper'},files,ALL); assert.match(r.find(x=>x.id==='edge-other-browser').message,/chrome/);
assert.equal(analyse(null,{}).find(x=>x.id==='manifest-present').status,'error');
assert.ok(RULES.length>=27);
const okAll=analyse(good,files,ALL), badAll=analyse(bad,{},ALL);
for (const rule of ALL_RULES) { assert.ok(badAll.find(x=>x.id===rule.id), `negative fixture covers ${rule.id}`); assert.ok(okAll.find(x=>x.id===rule.id), `positive fixture covers ${rule.id}`); if (rule.cws) assert.ok(rule.cwsUrl.startsWith('https://'), `${rule.id} links its policy`); }
console.log(`PASS: ${RULES.length} Chrome rules (${RULES.filter(x=>x.cws).length} mapped to violation IDs) + ${STORE_RULES.length} Firefox/Edge rules; good, broken, misunderstood, insecure, obfuscated, nested, Firefox and Edge fixtures covered.`);
