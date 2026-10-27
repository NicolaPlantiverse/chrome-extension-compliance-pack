// Deterministic Manifest V3 preflight. Each rule maps to an official Chrome Web Store violation ID.
export const CWS_SOURCE = 'https://developer.chrome.com/docs/webstore/troubleshooting';
export const CWS_PAGE_UPDATED = '2026-07-20';
export const RULES_VERIFIED = '2026-10-27';
const CWS_ANCHORS = {
  'Blue Argon':'additional-requirements-for-manifest-v3',
  'Yellow Magnesium':'does-not-work',
  'Purple Potassium':'excessive-permissions',
  'Yellow Zinc':'no-metadata',
  'Purple Lithium':'udp-disclosure-policy',
  'Purple Nickel':'udp-prominent-disclosure',
  'Purple Copper':'udp-secure',
  'Red Titanium':'obfuscation'
};
export function cwsLink(code) { return CWS_ANCHORS[code] ? `${CWS_SOURCE}#${CWS_ANCHORS[code]}` : ''; }

export const RULES = [
  ['zip-root','error','Yellow Magnesium','manifest.json is at the ZIP root','Zip the extension folder contents, not the folder itself: manifest.json must sit at the root of the package.'],
  ['manifest-present','error','Yellow Magnesium','Manifest V3 manifest is present','Add a valid manifest.json at the ZIP root.'],
  ['manifest-version','error','Yellow Magnesium','Manifest version is 3','Migrate to Manifest V3; Manifest V2 is not supported by this pack.'],
  ['name','error','Yellow Zinc','Extension name is present','Add a concise, meaningful name in manifest.json.'],
  ['version','error','Yellow Magnesium','Version is valid','Use 1–4 dot-separated integers, for example 1.0.0.'],
  ['description','warning','Yellow Zinc','Description is present and concise','Add a store-ready description that lists the main features.'],
  ['permissions-known','warning','Purple Potassium','Permissions are declared in a reviewable list','Explain every permission in the Privacy practices tab of the Developer Dashboard.'],
  ['permissions-sensitive','warning','Purple Potassium','Sensitive permissions are highlighted','Remove unused sensitive permissions and explain the remaining ones.'],
  ['permissions-unused','warning','Purple Potassium','Declared API permissions are used in the code','Remove permissions the code never calls: requested but unused permissions are a stated rejection reason.'],
  ['permissions-misunderstood','warning','Purple Potassium','No commonly misunderstood permission is requested','activeTab and tabs are not needed with broad host access; tabs only unlocks url, pendingUrl, title and favIconUrl; cookies and storage are not needed for document.cookie, Web Storage or IndexedDB.'],
  ['host-https','error','Purple Copper','Host permissions avoid broad insecure HTTP access','Prefer HTTPS origins and the narrowest possible match patterns.'],
  ['host-broad','warning','Purple Potassium','Host permissions are not unnecessarily broad','Replace <all_urls> or wildcard hosts with the smallest required scope.'],
  ['host-permissions','warning','Purple Potassium','Host permissions are explicitly reviewed','Document why each host is needed and when access occurs.'],
  ['insecure-endpoints','warning','Purple Copper','Code does not call plain HTTP or WS endpoints','Use HTTPS or WSS for every network request that can carry user data.'],
  ['remote-code','error','Blue Argon','No remote JavaScript execution is referenced','Bundle JavaScript with the extension; do not load remote scripts or eval-like code.'],
  ['obfuscation','warning','Red Titanium','No obfuscation pattern is detected','Ship readable or minified code; remove encoded payloads, escaped identifiers and obfuscator output.'],
  ['content-script-match','warning','Purple Potassium','Content scripts use scoped match patterns','Narrow matches and explain why pages need access.'],
  ['content-script-js','error','Yellow Magnesium','Content script files are local','List local .js files that exist in the package.'],
  ['csp','warning','Blue Argon','Extension pages have an explicit safe CSP','Set a restrictive extension_pages CSP without remote script sources.'],
  ['icon-paths','error','Yellow Zinc','Declared icons point to files in the ZIP','Include every icon file with a supported image extension.'],
  ['action-icon','warning','Yellow Magnesium','Action icons are present when configured','Provide local icons for the toolbar action.'],
  ['web-accessible','warning','','Web accessible resources are scoped','Use narrow matches and expose only files that page scripts truly need.'],
  ['background-service-worker','warning','Yellow Magnesium','Background service worker is local','Use a local service_worker path that exists in the package.'],
  ['html-paths','error','Yellow Magnesium','Declared extension HTML paths are local','Ensure options, popup and side panel paths exist in the ZIP.'],
  ['no-remote-permission','error','Blue Argon','No remote code permission is requested','Remove deprecated or unsupported remote-code patterns and permissions.'],
  ['privacy-policy','warning','Purple Lithium','Privacy policy need is assessed','Put a working privacy policy URL in the Dashboard privacy field (not in the description) and disclose data use before collecting it.'],
  ['zip-safe','pass','','ZIP contents are treated as inert data','Analysis reads text and metadata only; it never runs extension code.']
].map(([id,severity,cws,title,remediation])=>({id,severity,cws,cwsUrl:cwsLink(cws),title,remediation,store:'chrome'}));

// Firefox (addons.mozilla.org) and Microsoft Edge Add-ons rules, verified on 2026-10-27.
const AMO_POLICIES = 'https://extensionworkshop.com/documentation/publish/add-on-policies/';
const FF_CONSENT = 'https://extensionworkshop.com/documentation/develop/firefox-builtin-data-consent/';
const FF_BSS = 'https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/browser_specific_settings';
const FF_BG = 'https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json/background';
const EDGE_POLICIES = 'https://learn.microsoft.com/en-us/legal/microsoft-edge/extensions/developer-policies';
export const STORE_RULES = [
  ['ff-gecko-id','error','firefox','Firefox · add-on ID',FF_BSS,'Firefox add-on ID is declared','Add browser_specific_settings.gecko.id (for example "name@yourdomain.com"): Firefox needs it to sign a Manifest V3 extension and AMO does not assign one.'],
  ['ff-data-collection','error','firefox','Firefox · data consent',FF_CONSENT,'Firefox data collection is declared','Add browser_specific_settings.gecko.data_collection_permissions; use {"required":["none"]} if the extension collects nothing. Mandatory for new AMO submissions since 3 November 2025.'],
  ['ff-background','error','firefox','Firefox · background',FF_BG,'Background script runs in Firefox','Firefox does not support background.service_worker: add background.scripts with the same file. Chrome 121 and later ignore it.'],
  ['ff-source-code','warning','firefox','AMO policy 3.1',AMO_POLICIES,'Reviewers can read the submitted code','When code is minified, bundled or transpiled, AMO asks for the original source and the build instructions with the submission.'],
  ['edge-other-browser','warning','edge','Edge policy 1.1.2',EDGE_POLICIES,'Listing does not name other browsers','Remove "Chrome" or other browser names from the name and description: Edge policy 1.1.2 says extensions must not reference other browsers. The privacy policy should refer to Microsoft Edge.'],
  ['edge-certification-notes','pass','edge','Edge policy 1.3',EDGE_POLICIES,'Testing notes are prepared','If any feature needs an account or a server, give a test account and steps in Submission options > Notes for certification (Edge policies 1.3.1 and 1.3.2).']
].map(([id,severity,store,cws,cwsUrl,title,remediation])=>({id,severity,store,cws,cwsUrl,title,remediation}));
const FF_DATA = new Set(['personallyIdentifyingInfo','healthInfo','financialAndPaymentInfo','authenticationInfo','personalCommunications','locationInfo','browsingActivity','websiteContent','websiteActivity','searchTerms','bookmarksInfo','technicalAndInteraction','none']);
export const ALL_RULES = [...RULES, ...STORE_RULES];

const sensitive = new Set(['tabs','webRequest','webRequestBlocking','cookies','history','downloads','management','debugger','proxy','scripting']);
const dataAccess = new Set(['tabs','history','cookies','webRequest','webRequestBlocking','webNavigation','bookmarks','identity','identity.email','geolocation','clipboardRead','downloads','topSites','sessions','readingList','pageCapture','tabCapture','desktopCapture','scripting','userScripts','debugger','management','nativeMessaging']);
// Permission -> chrome.* namespaces that use it. Permissions absent here are not checked for use.
const API_PERMS = {
  alarms:['alarms'], bookmarks:['bookmarks'], browsingData:['browsingData'], contentSettings:['contentSettings'], contextMenus:['contextMenus'],
  cookies:['cookies'], debugger:['debugger'], declarativeContent:['declarativeContent'], declarativeNetRequest:['declarativeNetRequest'],
  declarativeNetRequestWithHostAccess:['declarativeNetRequest'], declarativeNetRequestFeedback:['declarativeNetRequest'], desktopCapture:['desktopCapture'],
  downloads:['downloads'], fontSettings:['fontSettings'], gcm:['gcm'], history:['history'], identity:['identity'], idle:['idle'], management:['management'],
  nativeMessaging:['runtime.connectNative','runtime.sendNativeMessage'], notifications:['notifications'], offscreen:['offscreen'], pageCapture:['pageCapture'],
  power:['power'], printerProvider:['printerProvider'], privacy:['privacy'], proxy:['proxy'], readingList:['readingList'], scripting:['scripting'], search:['search'],
  sessions:['sessions'], sidePanel:['sidePanel'], storage:['storage'], 'system.cpu':['system.cpu'], 'system.memory':['system.memory'], 'system.storage':['system.storage'],
  'system.display':['system.display'], tabCapture:['tabCapture'], tabGroups:['tabGroups'], tabs:['tabs'], topSites:['topSites'], tts:['tts'], ttsEngine:['ttsEngine'],
  userScripts:['userScripts'], webNavigation:['webNavigation'], webRequest:['webRequest'], webRequestBlocking:['webRequest']
};
const WEB_PERMS = {
  geolocation:/navigator\s*\.\s*geolocation/,
  clipboardRead:/navigator\s*\.\s*clipboard\s*\.\s*read|execCommand\s*\(\s*['"]paste/,
  clipboardWrite:/navigator\s*\.\s*clipboard\s*\.\s*write|execCommand\s*\(\s*['"](?:copy|cut)/
};
const remotePattern = /(?:https?:)?\/\/[^\s"']+\.js(?:\?[^\s"']*)?|<script[^>]+src\s*=\s*["']?(?:https?:)?\/\/|import\s*\(\s*["']https?:|\beval\s*\(/i;
const insecureCall = /(?:fetch|\.open|WebSocket|sendBeacon|EventSource)\s*\(\s*(?:['"`][A-Z]+['"`]\s*,\s*)?['"`]((?:http|ws):\/\/(?!localhost\b|127\.0\.0\.1\b|\[::1\])[^'"`\s]+)/g;
const versionRE = /^\d+(?:\.\d+){0,3}$/;

function result(rule, status, message, files = []) { return {...rule,status,message,files}; }
function fileExists(files, path) { return Object.prototype.hasOwnProperty.call(files, path); }
function isBroad(p) { return p==='<all_urls>'||/^\*:\/\/\*\//.test(p)||/^https?:\/\/\*\//.test(p); }
function apiUsed(code, ns) {
  const re = new RegExp('\\b(?:chrome|browser)' + ns.split('.').map(p=>`\\s*(?:\\.\\s*${p}\\b|\\[\\s*['"]${p}['"]\\s*\\])`).join(''));
  return re.test(code);
}
function obfuscationHits(path, src) {
  const why = [];
  if ((src.match(/\b_0x[0-9a-f]{4,6}\b/gi)||[]).length >= 10) why.push('obfuscator-style _0x identifiers');
  const escapes = (src.match(/\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|\\u\{[0-9a-f]{1,6}\}/gi)||[]).length;
  if (escapes >= 40 && escapes*4/Math.max(src.length,1) >= 0.10) why.push(`${escapes} hex/unicode escapes`);
  if (/\b(?:eval|Function)\s*\(\s*(?:window\.)?atob\s*\(/.test(src)) why.push('code decoded from base64 and executed');
  if (/atob\s*\(\s*['"][A-Za-z0-9+/=]{200,}['"]/.test(src)) why.push('long base64 payload');
  return why.length ? `${path} (${why.join(', ')})` : '';
}

// Accepts a ZIP whose files sit under one top folder and reports it as a packaging problem.
export function normaliseRoot(files) {
  if (fileExists(files,'manifest.json')) return {files, nested:''};
  const nested = Object.keys(files).filter(p=>/^[^/]+\/manifest\.json$/.test(p));
  if (nested.length !== 1) return {files, nested:''};
  const prefix = nested[0].slice(0, -'manifest.json'.length); const out = {};
  for (const [p,v] of Object.entries(files)) if (p.startsWith(prefix)) out[p.slice(prefix.length)] = v;
  return {files:out, nested:prefix};
}

export function analyse(manifest, files = {}, opts = {}) {
  const out=[]; const add=(id,status,message,filesFound=[])=>out.push(result(RULES.find(r=>r.id===id),status,message,filesFound));
  add('zip-root', opts.nested?'error':'pass', opts.nested?`manifest.json is inside the folder "${opts.nested}"; the store expects it at the root`:'manifest.json is at the package root',[opts.nested?`${opts.nested}manifest.json`:'manifest.json']);
  if (!manifest || typeof manifest !== 'object') { add('manifest-present','error','manifest.json is missing or is not a JSON object',['manifest.json']); return out; }
  add('manifest-present','pass','manifest.json parsed successfully',['manifest.json']);
  add('manifest-version', manifest.manifest_version===3?'pass':'error', manifest.manifest_version===3?'Manifest V3 detected':'Expected manifest_version: 3',['manifest.json']);
  add('name', typeof manifest.name==='string'&&manifest.name.trim()?'pass':'error', typeof manifest.name==='string'&&manifest.name.trim()?'Extension name found':'Missing extension name',['manifest.json']);
  add('version', typeof manifest.version==='string'&&versionRE.test(manifest.version)?'pass':'error', typeof manifest.version==='string'&&versionRE.test(manifest.version)?`Version ${manifest.version} is valid`:'Version must contain 1–4 numeric components',['manifest.json']);
  const desc=typeof manifest.description==='string'&&manifest.description.trim();
  add('description',desc?'pass':'warning',desc?'Description found':'Description is missing; add one before submission',['manifest.json']);
  const perms=[...(manifest.permissions||[]),...(manifest.optional_permissions||[])];
  add('permissions-known','pass',perms.length?`${perms.length} permission(s) detected`:'No API permissions declared',['manifest.json']);
  const sens=perms.filter(p=>sensitive.has(p));
  add('permissions-sensitive',sens.length?'warning':'pass',sens.length?`Review sensitive permission(s): ${sens.join(', ')}`:'No common sensitive permissions detected',['manifest.json']);
  const codeFiles=Object.entries(files).filter(([p])=>/\.(m?js|html?)$/i.test(p)); const code=codeFiles.map(([,v])=>v).join('\n');
  const usedByManifest = p => (p==='declarativeNetRequest'&&manifest.declarative_net_request?.rule_resources?.length) || (p==='sidePanel'&&manifest.side_panel) || (p==='ttsEngine'&&manifest.tts_engine);
  const unused=perms.filter(p=>!usedByManifest(p) && (API_PERMS[p] ? !API_PERMS[p].some(ns=>apiUsed(code,ns)) : WEB_PERMS[p] ? !WEB_PERMS[p].test(code) : false));
  add('permissions-unused',unused.length?'warning':'pass',unused.length?`No code reference found for: ${unused.join(', ')}. Remove them or check for dynamic access`:'Every checkable permission is referenced in the code',codeFiles.map(([p])=>p));
  const hosts=[...(manifest.host_permissions||[]),...(manifest.optional_host_permissions||[])];
  const cs=manifest.content_scripts||[]; const matches=cs.flatMap(x=>x.matches||[]); const csjs=cs.flatMap(x=>x.js||[]);
  const broadAccess=[...hosts,...matches].some(isBroad); const mis=[];
  if (perms.includes('activeTab')&&broadAccess) mis.push('activeTab is redundant with broad host access');
  if (perms.includes('tabs')&&broadAccess) mis.push('tabs is redundant with broad host access');
  else if (perms.includes('tabs')&&!/\.\s*(?:url|pendingUrl|title|favIconUrl)\b/.test(code)) mis.push('tabs is only needed to read url, pendingUrl, title or favIconUrl, and the code reads none of them');
  if (perms.includes('cookies')&&!apiUsed(code,'cookies')&&/document\s*\.\s*cookie|cookieStore/.test(code)) mis.push('cookies is not needed for document.cookie or the Cookie Store API');
  if (perms.includes('storage')&&!apiUsed(code,'storage')&&/localStorage|sessionStorage|indexedDB/.test(code)) mis.push('storage is not needed for Web Storage or IndexedDB');
  add('permissions-misunderstood',mis.length?'warning':'pass',mis.length?mis.join('; '):'No commonly misunderstood permission pattern found',['manifest.json']);
  const insecure=hosts.filter(h=>/^http:\/\//i.test(h));
  add('host-https',insecure.length?'error':'pass',insecure.length?`Insecure HTTP host permission(s): ${insecure.join(', ')}`:'Host permissions use HTTPS or non-HTTP schemes',['manifest.json']);
  const broad=hosts.filter(isBroad);
  add('host-broad',broad.length?'warning':'pass',broad.length?`Broad host permission(s): ${broad.join(', ')}`:'No broad host pattern detected',['manifest.json']);
  add('host-permissions',hosts.length?'warning':'pass',hosts.length?'Document each host permission in the justification template':'No host permissions declared',['manifest.json']);
  const plain=[]; for (const [p,v] of codeFiles) for (const m of v.matchAll(insecureCall)) plain.push(`${p}: ${m[1]}`);
  add('insecure-endpoints',plain.length?'warning':'pass',plain.length?`Plain HTTP/WS endpoint(s) in network calls: ${plain.slice(0,5).join('; ')}`:'No plain HTTP or WS endpoint found in network calls',plain.map(x=>x.split(':')[0]));
  const text=Object.entries(files).filter(([p])=>/\.(m?js|html?|json|css)$/i.test(p)).map(([p,v])=>`${p}\n${v}`).join('\n');
  add('remote-code',remotePattern.test(text)?'error':'pass',remotePattern.test(text)?'Possible remote script or eval-like code reference found':'No common remote-code pattern found',Object.keys(files).filter(p=>/\.(m?js|html?)$/i.test(p)));
  const obf=codeFiles.filter(([p])=>/\.m?js$/i.test(p)).map(([p,v])=>obfuscationHits(p,v)).filter(Boolean);
  add('obfuscation',obf.length?'warning':'pass',obf.length?`Possible obfuscation (minification is allowed, obfuscation is not): ${obf.join('; ')}`:'No obfuscation pattern found; minified code is allowed',obf.map(x=>x.split(' (')[0]));
  const broadCS=matches.filter(isBroad);
  add('content-script-match',broadCS.length?'warning':'pass',broadCS.length?`Broad content-script match: ${broadCS.join(', ')}`:cs.length?'Content-script matches are scoped':'No content scripts declared',['manifest.json']);
  const missingCS=csjs.filter(p=>!fileExists(files,p)); add('content-script-js',missingCS.length?'error':'pass',missingCS.length?`Missing content script file(s): ${missingCS.join(', ')}`:'Content script files are local and present',missingCS);
  const csp=(manifest.content_security_policy||{}).extension_pages||''; const badCsp=/https?:\/\//i.test(csp)||/unsafe-eval/i.test(csp);
  add('csp',!csp||badCsp?'warning':'pass',!csp?'No explicit extension_pages CSP found':badCsp?'CSP contains a remote source or unsafe-eval':'Explicit extension_pages CSP is restrictive',['manifest.json']);
  const icons=Object.values(manifest.icons||{}); const missingIcons=icons.filter(p=>!fileExists(files,p)); add('icon-paths',missingIcons.length?'error':icons.length?'pass':'warning',missingIcons.length?`Missing icon file(s): ${missingIcons.join(', ')}`:icons.length?'Icon files are present':'No icons declared in manifest.json; Chrome shows a generic icon',missingIcons);
  const actionIcons=manifest.action?.default_icon?(typeof manifest.action.default_icon==='string'?[manifest.action.default_icon]:Object.values(manifest.action.default_icon)):[]; const missAction=actionIcons.filter(p=>!fileExists(files,p)); add('action-icon',missAction.length?'warning':'pass',missAction.length?`Missing action icon file(s): ${missAction.join(', ')}`:actionIcons.length?'Action icon files are present':'No action icon configured',missAction);
  const war=manifest.web_accessible_resources||[]; const warBroad=war.flatMap(x=>x.matches||[]).filter(m=>m==='<all_urls>'); add('web-accessible',warBroad.length?'warning':'pass',warBroad.length?'Web accessible resources match all URLs':'Web accessible resources are absent or scoped',['manifest.json']);
  const sw=manifest.background?.service_worker; add('background-service-worker',sw&&!fileExists(files,sw)?'warning':'pass',sw&&!fileExists(files,sw)?`Missing service worker: ${sw}`:sw?'Local service worker is present':'No service worker configured',sw?[sw]:[]);
  const htmls=manifest.options_page?[manifest.options_page]:[]; if(manifest.options_ui?.page) htmls.push(manifest.options_ui.page); if(manifest.action?.default_popup) htmls.push(manifest.action.default_popup); if(manifest.side_panel?.default_path) htmls.push(manifest.side_panel.default_path); const missingHtml=htmls.filter(p=>!fileExists(files,p)); add('html-paths',missingHtml.length?'error':'pass',missingHtml.length?`Missing HTML path(s): ${missingHtml.join(', ')}`:htmls.length?'Declared HTML paths are present':'No extension HTML entry points configured',missingHtml);
  add('no-remote-permission',perms.some(p=>/remote/i.test(p))?'error':'pass',perms.some(p=>/remote/i.test(p))?'Unsupported remote-code permission detected':'No remote-code permission detected',['manifest.json']);
  const data=perms.filter(p=>dataAccess.has(p)); const reach=hosts.length||matches.length;
  add('privacy-policy',data.length||reach?'warning':'pass',data.length||reach?`Access to user data (${[...data,...(reach?['page or host access']:[])].join(', ')}): if any user data is collected, a working privacy policy URL is required in the Dashboard privacy field (Purple Lithium) and use must be disclosed with consent first (Purple Nickel)`:'No permission or host access that typically reaches user data',['manifest.json']);
  add('zip-safe','pass','ZIP entries were inspected as inert text and metadata only');
  const stores = opts.stores || ['chrome'];
  const put=(id,status,message,filesFound=[])=>out.push(result(STORE_RULES.find(r=>r.id===id),status,message,filesFound));
  if (stores.includes('firefox')) {
    const gecko = manifest.browser_specific_settings?.gecko || manifest.applications?.gecko || {};
    put('ff-gecko-id', gecko.id ? 'pass' : manifest.manifest_version===3 ? 'error' : 'warning', gecko.id ? `Add-on ID ${gecko.id}` : 'browser_specific_settings.gecko.id is missing', ['manifest.json']);
    const dc = gecko.data_collection_permissions; const bad = [];
    if (dc) {
      for (const v of [...(dc.required||[]),...(dc.optional||[])]) if (!FF_DATA.has(v)) bad.push(`unknown value "${v}"`);
      if ((dc.required||[]).includes('technicalAndInteraction')) bad.push('technicalAndInteraction must be optional, not required');
      if ((dc.optional||[]).includes('none')) bad.push('"none" belongs in required only');
      if (!(dc.required||[]).length) bad.push('required list is empty; use ["none"] if nothing is collected');
    }
    put('ff-data-collection', !dc ? 'error' : bad.length ? 'error' : 'pass', !dc ? 'data_collection_permissions is missing: new submissions to addons.mozilla.org are refused without it' : bad.length ? bad.join('; ') : `Declared: required ${JSON.stringify(dc.required)}${dc.optional?.length?`, optional ${JSON.stringify(dc.optional)}`:''}`, ['manifest.json']);
    const bg = manifest.background || {};
    put('ff-background', bg.service_worker && !bg.scripts && !bg.page ? 'error' : 'pass', bg.service_worker && !bg.scripts && !bg.page ? `Only background.service_worker ("${bg.service_worker}") is declared; Firefox will not run it` : bg.service_worker ? 'background.scripts is declared next to service_worker' : 'No service-worker-only background', ['manifest.json']);
    const built = codeFiles.filter(([p,v])=>/\.m?js$/i.test(p) && (/__webpack_require__|__vite__|sourceMappingURL=|System\.register\(/.test(v) || v.split('\n').some(l=>l.length>1500))).map(([p])=>p);
    put('ff-source-code', built.length ? 'warning' : 'pass', built.length ? `Minified or bundled code: ${built.slice(0,5).join(', ')}. Prepare the source archive and build steps for AMO` : 'No minified or bundled file detected', built);
  }
  if (stores.includes('edge')) {
    const listing = [manifest.name, manifest.short_name, manifest.description].filter(x=>typeof x==='string').join(' ');
    const named = [...new Set((listing.match(/\b(?:google\s+)?chrome\b|\bfirefox\b|\bsafari\b|\bopera\b|\bbrave\b/gi)||[]).map(x=>x.toLowerCase()))];
    put('edge-other-browser', named.length ? 'warning' : 'pass', named.length ? `Name or description mentions: ${named.join(', ')}` : 'Name and description do not mention other browsers', ['manifest.json']);
    put('edge-certification-notes', 'pass', 'Reminder: add test account and steps in Notes for certification if needed');
  }
  return out;
}

export function summary(results) { return {pass:results.filter(r=>r.status==='pass').length,warning:results.filter(r=>r.status==='warning').length,error:results.filter(r=>r.status==='error').length}; }
export function permissionRows(manifest={}) { const rows=[]; for (const p of [...(manifest.permissions||[]),...(manifest.optional_permissions||[])]) rows.push({kind:'API permission',permission:p,why:`Explain the exact user-facing feature that needs “${p}”, when it runs, and why a narrower permission is insufficient.`}); for (const p of [...(manifest.host_permissions||[]),...(manifest.optional_host_permissions||[])]) rows.push({kind:'Host permission',permission:p,why:`Explain which pages “${p}” covers, what data is read or changed, and how access benefits the user.`}); return rows; }
