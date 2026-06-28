package reporter

// htmlTemplateSrc is a standalone, offline glassmorphism dashboard. All CSS and
// JS are inline so the report works in air-gapped environments.
const htmlTemplateSrc = `<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
:root{
  --grad1:#6d28d9;--grad2:#2563eb;--grad3:#0891b2;
  --bg0:#0a0a14;--bg1:#12121f;
  --glass:rgba(255,255,255,.06);--glass-strong:rgba(255,255,255,.10);
  --stroke:rgba(255,255,255,.14);--stroke-soft:rgba(255,255,255,.08);
  --fg:#eef1f8;--muted:#9aa3b8;
  --crit:#ff4d6d;--high:#ff8c42;--med:#ffd166;--low:#06d6a0;--info:#4cc9f0;
  --shadow:0 8px 32px rgba(0,0,0,.45);
}
[data-theme="light"]{
  --bg0:#eef2fb;--bg1:#dfe7f5;
  --glass:rgba(255,255,255,.55);--glass-strong:rgba(255,255,255,.72);
  --stroke:rgba(20,30,60,.12);--stroke-soft:rgba(20,30,60,.08);
  --fg:#101426;--muted:#4a5570;--shadow:0 8px 32px rgba(40,60,120,.18);
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;color:var(--fg);font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:var(--bg0);position:relative;min-height:100vh;overflow-x:hidden;
}
body::before{
  content:"";position:fixed;inset:0;z-index:-2;
  background:
    radial-gradient(40% 50% at 12% 8%, rgba(109,40,217,.55), transparent 60%),
    radial-gradient(45% 55% at 88% 14%, rgba(37,99,235,.50), transparent 60%),
    radial-gradient(55% 60% at 50% 100%, rgba(8,145,178,.40), transparent 65%),
    linear-gradient(160deg,var(--bg0),var(--bg1));
}
body::after{content:"";position:fixed;inset:0;z-index:-1;opacity:.05;
  background-image:radial-gradient(currentColor 1px,transparent 1px);background-size:22px 22px;}

.glass{
  background:var(--glass);backdrop-filter:blur(18px) saturate(160%);
  -webkit-backdrop-filter:blur(18px) saturate(160%);
  border:1px solid var(--stroke);border-radius:20px;box-shadow:var(--shadow);
}
.wrap{max-width:1180px;margin:0 auto;padding:32px 24px 80px}

header.hero{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;
  padding:28px 32px;margin-bottom:24px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:16px}
.logo{width:54px;height:54px;border-radius:16px;display:grid;place-items:center;font-weight:800;font-size:22px;
  background:linear-gradient(135deg,var(--grad1),var(--grad3));color:#fff;box-shadow:0 6px 20px rgba(109,40,217,.5)}
.brand h1{margin:0;font-size:22px;letter-spacing:-.02em}
.brand .sub{color:var(--muted);font-size:12.5px;margin-top:2px}
.meta{text-align:right;font-size:12.5px;color:var(--muted);line-height:1.7}
.meta b{color:var(--fg);font-weight:600}
.chip{display:inline-block;padding:3px 10px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.04em;
  border:1px solid var(--stroke);background:var(--glass-strong)}

.toolbar{display:flex;gap:10px;margin:0 0 22px;flex-wrap:wrap;align-items:center}
button,select,input{font-family:inherit;font-size:13px;color:var(--fg);
  background:var(--glass-strong);border:1px solid var(--stroke);border-radius:12px;padding:9px 14px;cursor:pointer;
  backdrop-filter:blur(10px);transition:.18s}
button:hover,select:hover{border-color:var(--grad2);transform:translateY(-1px)}
input{cursor:text;min-width:200px}
.spacer{flex:1}

.top{display:grid;grid-template-columns:300px 1fr;gap:20px;margin-bottom:20px}
@media(max-width:820px){.top{grid-template-columns:1fr}}
.gauge-card{padding:26px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge-wrap{position:relative;width:200px;height:200px}
.gauge-wrap .val{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge-wrap .num{font-size:46px;font-weight:800;line-height:1}
.gauge-wrap .lvl{font-size:13px;font-weight:700;letter-spacing:.12em;margin-top:6px}
.gauge-wrap .of{font-size:11px;color:var(--muted)}

.stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px}
.stat{padding:18px 20px;position:relative;overflow:hidden}
.stat .k{font-size:11.5px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:600}
.stat .v{font-size:34px;font-weight:800;margin-top:6px;line-height:1}
.stat .accent{position:absolute;right:-20px;top:-20px;width:80px;height:80px;border-radius:50%;filter:blur(6px);opacity:.5}

.sevbars{padding:22px 26px;margin-bottom:20px}
.sevrow{display:grid;grid-template-columns:90px 1fr 48px;align-items:center;gap:14px;margin:11px 0}
.sevrow .lbl{font-size:12.5px;font-weight:700;letter-spacing:.04em}
.track{height:12px;border-radius:999px;background:var(--stroke-soft);overflow:hidden}
.track>span{display:block;height:100%;border-radius:999px;transition:width .9s cubic-bezier(.2,.8,.2,1)}
.sevrow .cnt{text-align:right;font-weight:700;font-variant-numeric:tabular-nums}

h2{font-size:14px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);margin:30px 4px 14px;font-weight:700}

.heat{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;padding:22px;margin-bottom:8px}
@media(max-width:620px){.heat{grid-template-columns:repeat(2,1fr)}}
.tile{padding:14px 12px;border-radius:14px;border:1px solid var(--stroke-soft);background:var(--glass-strong);
  text-align:center;transition:.2s;position:relative}
.tile .id{font-weight:800;font-size:13px}
.tile .nm{font-size:10.5px;color:var(--muted);margin:4px 0 8px;min-height:26px;line-height:1.3}
.tile .ct{font-size:20px;font-weight:800}
.tile.clean{opacity:.55}
.tile.hit{border-color:var(--crit);box-shadow:0 0 0 1px var(--crit),0 8px 24px rgba(255,77,109,.25)}
.tile.hit .ct{color:var(--crit)}

.cols{display:grid;grid-template-columns:1fr 1fr;gap:20px}
@media(max-width:820px){.cols{grid-template-columns:1fr}}
.listcard{padding:20px 24px}
.listcard table{width:100%;border-collapse:collapse;font-size:12.5px}
.listcard td{padding:7px 6px;border-bottom:1px solid var(--stroke-soft);vertical-align:top}
.listcard td.k{font-weight:700;white-space:nowrap;color:var(--fg)}
.listcard td.d{color:var(--muted)}

.findings{padding:8px}
.fcard{padding:18px 20px;border-radius:16px;border:1px solid var(--stroke-soft);background:var(--glass-strong);
  margin:12px;border-left:4px solid var(--muted);transition:.2s;cursor:pointer}
.fcard:hover{transform:translateY(-2px);border-color:var(--stroke)}
.fhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.badge{padding:3px 11px;border-radius:999px;font-size:10.5px;font-weight:800;letter-spacing:.05em;color:#0a0a14}
.fid{font-family:'SF Mono',ui-monospace,Menlo,monospace;font-size:11.5px;color:var(--muted)}
.ftitle{font-weight:700;font-size:14.5px;flex:1;min-width:200px}
.frisk{font-weight:800;font-variant-numeric:tabular-nums}
.floc{font-size:11.5px;color:var(--muted);margin-top:7px;font-family:'SF Mono',ui-monospace,monospace}
.fdetail{display:none;margin-top:14px;padding-top:14px;border-top:1px dashed var(--stroke);font-size:12.8px;line-height:1.65}
.fcard.open .fdetail{display:block}
.fdetail .row{margin:7px 0}.fdetail .row b{color:var(--fg)}
.tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}
.tag{font-size:10px;padding:2px 8px;border-radius:6px;background:var(--glass);border:1px solid var(--stroke-soft);color:var(--muted)}
.rem{margin-top:10px;padding:10px 12px;border-radius:10px;background:rgba(6,214,160,.10);border:1px solid rgba(6,214,160,.3)}
.empty{text-align:center;padding:50px;color:var(--muted)}

footer{text-align:center;color:var(--muted);font-size:11.5px;margin-top:40px}
.bd-crit{border-left-color:var(--crit)!important}.bd-high{border-left-color:var(--high)!important}
.bd-med{border-left-color:var(--med)!important}.bd-low{border-left-color:var(--low)!important}.bd-info{border-left-color:var(--info)!important}

@media print{
  body::before,body::after{display:none}body{background:#fff;color:#000}
  .glass,.fcard,.tile{background:#fff!important;border-color:#ccc!important;box-shadow:none!important;backdrop-filter:none!important}
  .toolbar{display:none}.fcard .fdetail{display:block!important}
}
</style>
</head>
<body>
<div class="wrap">

<header class="hero glass">
  <div class="brand">
    <div class="logo">S</div>
    <div>
      <h1>{{.Title}}</h1>
      <div class="sub">{{if .Org}}{{.Org}}{{end}}{{if .Assessor}} · Assessor: {{.Assessor}}{{end}}</div>
      {{if .Classification}}<div style="margin-top:8px"><span class="chip" style="color:var(--high)">{{.Classification}}</span></div>{{end}}
    </div>
  </div>
  <div class="meta">
    <div><b>Agent:</b> {{.Agent}}</div>
    <div><b>Target:</b> {{.Target}}</div>
    <div><b>Scan:</b> {{.Timestamp}}</div>
    <div><b>Duration:</b> {{.Duration}} · SEMAR {{.Version}}</div>
  </div>
</header>

<div class="toolbar">
  <input id="q" placeholder="Search findings…" oninput="render()">
  <select id="sevFilter" onchange="render()">
    <option value="">All severities</option>
    <option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option>
  </select>
  <span class="spacer"></span>
  <button onclick="expandAll()">Expand all</button>
  <button onclick="exportCSV()">⬇ Export CSV</button>
  <button onclick="window.print()">🖨 Print / PDF</button>
  <button onclick="toggleTheme()">◑ Theme</button>
</div>

<div class="top">
  <div class="gauge-card glass">
    <div class="gauge-wrap">
      <svg width="200" height="200" viewBox="0 0 200 200">
        <defs>
          <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stop-color="{{.RiskColor}}"/>
            <stop offset="1" stop-color="var(--grad2)"/>
          </linearGradient>
        </defs>
        <circle cx="100" cy="100" r="80" fill="none" stroke="var(--stroke-soft)" stroke-width="16"/>
        <circle cx="100" cy="100" r="80" fill="none" stroke="url(#g)" stroke-width="16"
          stroke-linecap="round" stroke-dasharray="{{.GaugeDash}}" transform="rotate(-90 100 100)"/>
      </svg>
      <div class="val">
        <div class="num" style="color:{{.RiskColor}}">{{printf "%.1f" .RiskScore}}</div>
        <div class="lvl" style="color:{{.RiskColor}}">{{.RiskLevel}}</div>
        <div class="of">overall risk / 10</div>
      </div>
    </div>
  </div>

  <div class="stat-grid">
    <div class="stat glass"><div class="accent" style="background:var(--grad2)"></div><div class="k">Total findings</div><div class="v">{{.Total}}</div></div>
    {{range .Severities}}
    <div class="stat glass"><div class="accent" style="background:{{.Color}}"></div><div class="k" style="color:{{.Color}}">{{.Name}}</div><div class="v">{{.Count}}</div></div>
    {{end}}
    <div class="stat glass"><div class="accent" style="background:var(--grad3)"></div><div class="k">Files scanned</div><div class="v">{{.FilesScanned}}</div></div>
    <div class="stat glass"><div class="accent" style="background:var(--grad1)"></div><div class="k">Rules evaluated</div><div class="v">{{.RulesCount}}</div></div>
  </div>
</div>

<div class="sevbars glass">
  {{range .Severities}}
  <div class="sevrow">
    <div class="lbl" style="color:{{.Color}}">{{.Name}}</div>
    <div class="track"><span style="width:{{printf "%.1f" .Percent}}%;background:linear-gradient(90deg,{{.Color}},{{.Color}}aa)"></span></div>
    <div class="cnt">{{.Count}}</div>
  </div>
  {{end}}
</div>

<h2>OWASP LLM Top 10 (2025) · Coverage {{.OWASPCoverage}}</h2>
<div class="heat glass">
  {{range .OWASP}}
  <div class="tile {{if gt .Count 0}}hit{{else}}clean{{end}}">
    <div class="id">{{.ID}}</div><div class="nm">{{.Name}}</div><div class="ct">{{.Count}}</div>
  </div>
  {{end}}
</div>

<div class="cols">
  <div>
    <h2>MITRE ATLAS TTPs</h2>
    <div class="listcard glass">
      {{if .MITRE}}<table>{{range .MITRE}}<tr><td class="k">{{.ID}}</td><td class="d">{{.Name}}</td></tr>{{end}}</table>
      {{else}}<div class="empty">No ATLAS TTPs mapped.</div>{{end}}
    </div>
  </div>
  <div>
    <h2>NIST AI RMF Controls</h2>
    <div class="listcard glass">
      {{if .NIST}}<table>{{range .NIST}}<tr><td class="k">{{.ID}}</td><td class="d">{{.Name}}</td></tr>{{end}}</table>
      {{else}}<div class="empty">No controls referenced.</div>{{end}}
    </div>
  </div>
</div>

<h2>Findings <span id="fcount" style="color:var(--fg)"></span></h2>
<div class="findings glass" id="findings"></div>

<footer>
  Generated by <b>SEMAR</b> {{.Version}} · Scan {{.ScanID}} · Read-only AI agent security audit<br>
  <i>"Sing ngerti kabeh, nanging ora ngancam"</i>
</footer>
</div>

<script>
const FINDINGS = {{.FindingsJSON}};
const COLORS={CRITICAL:'#ff4d6d',HIGH:'#ff8c42',MEDIUM:'#ffd166',LOW:'#06d6a0',INFO:'#4cc9f0'};
const BD={CRITICAL:'bd-crit',HIGH:'bd-high',MEDIUM:'bd-med',LOW:'bd-low',INFO:'bd-info'};
function esc(s){return (s==null?'':String(s)).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
function toggleTheme(){const h=document.documentElement;h.dataset.theme=h.dataset.theme==='dark'?'light':'dark';}
function tags(arr,pfx){return (arr||[]).map(x=>'<span class="tag">'+pfx+esc(x)+'</span>').join('');}
function render(){
  const sev=document.getElementById('sevFilter').value;
  const q=document.getElementById('q').value.toLowerCase();
  const box=document.getElementById('findings');box.innerHTML='';
  const list=FINDINGS.filter(f=>(!sev||f.severity===sev)&&(!q||(f.title+f.id+(f.file_path||'')+(f.description||'')).toLowerCase().includes(q)));
  document.getElementById('fcount').textContent='('+list.length+')';
  if(!list.length){box.innerHTML='<div class="empty">No findings match your filter. 🎉</div>';return;}
  list.forEach(f=>{
    const c=COLORS[f.severity]||'#888';
    const el=document.createElement('div');el.className='fcard '+(BD[f.severity]||'');
    el.onclick=()=>el.classList.toggle('open');
    let loc=f.file_path?('<div class="floc">📄 '+esc(f.file_path)+(f.line?':'+f.line:'')+'</div>'):'';
    let rem=f.remediation?('<div class="rem"><b>✓ Remediation:</b> '+esc(f.remediation)+(f.remediation_code?'<pre style="white-space:pre-wrap;margin:8px 0 0">'+esc(f.remediation_code)+'</pre>':'')+'</div>'):'';
    let refs=(f.references||[]).map(r=>'<a href="'+esc(r)+'" style="color:var(--info)">'+esc(r)+'</a>').join('<br>');
    el.innerHTML=
      '<div class="fhead"><span class="badge" style="background:'+c+'">'+esc(f.severity)+'</span>'+
      '<span class="fid">'+esc(f.id)+'</span><span class="ftitle">'+esc(f.title)+'</span>'+
      '<span class="frisk" style="color:'+c+'">'+(f.risk_score||0).toFixed(1)+'</span></div>'+loc+
      '<div class="tags">'+tags(f.owasp,'')+tags(f.cwe,'')+tags(f.mitre,'')+'</div>'+
      '<div class="fdetail">'+
        (f.description?'<div class="row"><b>Description:</b> '+esc(f.description)+'</div>':'')+
        (f.impact?'<div class="row"><b>Impact:</b> '+esc(f.impact)+'</div>':'')+
        (f.evidence?'<div class="row"><b>Evidence:</b> '+esc(f.evidence)+'</div>':'')+
        '<div class="row"><b>Confidence:</b> '+esc(f.confidence)+' · <b>Category:</b> '+esc(f.category)+'</div>'+
        (f.nist&&f.nist.length?'<div class="row"><b>NIST:</b> '+f.nist.join(', ')+'</div>':'')+
        rem+(refs?'<div class="row" style="margin-top:10px"><b>References:</b><br>'+refs+'</div>':'')+
      '</div>';
    box.appendChild(el);
  });
}
function expandAll(){document.querySelectorAll('.fcard').forEach(e=>e.classList.toggle('open'));}
function exportCSV(){
  let csv='id,severity,confidence,title,file,line,risk,owasp,cwe,mitre\n';
  FINDINGS.forEach(f=>{csv+=[f.id,f.severity,f.confidence,'"'+(f.title||'').replace(/"/g,'""')+'"',f.file_path||'',f.line||0,f.risk_score||0,'"'+(f.owasp||[]).join(';')+'"','"'+(f.cwe||[]).join(';')+'"','"'+(f.mitre||[]).join(';')+'"'].join(',')+'\n';});
  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));a.download='semar-findings.csv';a.click();
}
render();
</script>
</body>
</html>`
