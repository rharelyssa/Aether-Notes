/**
 * Aether Notes — XSS Security Tests
 * Run: node security-tests/xss.test.js
 * 
 * Tests the safeRenderMarkdown() pipeline against known XSS payloads.
 * All 15 payloads should be neutralized (0 vulnerabilities).
 */

function sanitizeHref(h) {
  if(!h) return "#";
  if(h.startsWith('//')) return "#";
  if(h.includes('../') || h.includes('..\\')) return "#";
  if(h.includes('\x00')) return "#";
  try {
    const u = new URL(h);
    if(["http:","https:","mailto:"].includes(u.protocol)) return h;
    return "#";
  } catch {}
  return /^[a-zA-Z0-9/_\-.#?=&%]+$/.test(h) ? h : "#";
}

function renderMarkdown(raw) {
  if (!raw) return "";
  let t = raw.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  t = t.replace(/\[\[([^\]]+)\]\]/g, (_,title) =>
    `<span class="wiki-link" data-wiki="${title.replace(/"/g,"&quot;")}">${title}</span>`
  );
  return t
    .replace(/^### (.+)$/gm,"<h3>$1</h3>").replace(/^## (.+)$/gm,"<h2>$1</h2>").replace(/^# (.+)$/gm,"<h1>$1</h1>")
    .replace(/\*\*(.+?)\*\*/g,"<strong>$1</strong>").replace(/\*(.+?)\*/g,"<em>$1</em>")
    .replace(/`(.+?)`/g,"<code>$1</code>")
    .replace(/^- (.+)$/gm,"<li>$1</li>")
    .replace(/^&gt; (.+)$/gm,"<blockquote>$1</blockquote>")
    .replace(/\[(.+?)\]\((.+?)\)/g,(_,txt,href)=>`<a href="${sanitizeHref(href)}" target="_blank" rel="noopener noreferrer">${txt}</a>`)
    .replace(/^(?!<[hubloa]|<blockquote)(.+)$/gm,"<p>$1</p>");
}

// Checks for EXECUTABLE (unescaped) dangerous HTML in output
function isReallyVulnerable(html) {
  const realTags = [
    /<script[\s>]/i,
    /<iframe[\s>]/i,
    /<img[^>]+onerror\s*=/i,
    /<[a-z]+[^>]+on\w+\s*=/i,
    /<a[^>]+href\s*=\s*["']?javascript:/i,
    /<a[^>]+href\s*=\s*["']?data:/i,
    /<svg[^>]+onload\s*=/i,
  ];
  return realTags.filter(rx => rx.test(html));
}

const payloads = [
  { name:"script tag",          p:"<script>alert(1)</script>" },
  { name:"img onerror",         p:"<img src=x onerror=alert(1)>" },
  { name:"svg onload",          p:"<svg onload=alert(1)>" },
  { name:"iframe js",           p:"<iframe src=javascript:alert(1)>" },
  { name:"a javascript href",   p:"[click](javascript:alert(1))" },
  { name:"a data href",         p:'<a href="data:text/html,<script>alert(1)</script>">x</a>' },
  { name:"style js url",        p:'<div style="background:url(javascript:alert(1))">x</div>' },
  { name:"onmouseover",         p:"<p onmouseover=alert(1)>x</p>" },
  { name:"eval atob",           p:'<img onerror="eval(atob(\'YWxlcnQoMSk=\'))">'},
  { name:"wiki script inject",  p:"[[<script>alert(1)</script>]]" },
  { name:"markdown img onerror",p:'![x](x" onerror="alert(1)")' },
  { name:"newline href inject", p:"[x](https://safe.com\nonerror=alert(1))" },
  { name:"nested quotes",       p:'"><img src=x onerror=alert(1)>' },
  { name:"null byte",           p:"<scr\x00ipt>alert(1)</scr\x00ipt>" },
  { name:"uppercase tag",       p:"<SCRIPT>alert(1)</SCRIPT>" },
];

const hrefTests = [
  ["javascript:alert(1)",       "#", "BLOCK"],
  ["data:text/html,<script>",   "#", "BLOCK"],
  ["vbscript:alert(1)",         "#", "BLOCK"],
  ["//evil.com",                "#", "BLOCK"],
  ["../../../etc/passwd",       "#", "BLOCK"],
  ["\x00javascript:alert(1)",   "#", "BLOCK"],
  ["https://safe.com/path?q=1", "https://safe.com/path?q=1", "ALLOW"],
  ["http://safe.com",           "http://safe.com", "ALLOW"],
  ["mailto:test@test.com",      "mailto:test@test.com", "ALLOW"],
  ["#section",                  "#section", "ALLOW"],
];

let pass = 0, fail = 0;

console.log("=== Aether Notes XSS Security Tests ===\n");
console.log("--- Payload Tests ---");

payloads.forEach(({name, p}) => {
  const html = renderMarkdown(p);
  const vulns = isReallyVulnerable(html);
  if(vulns.length > 0){
    fail++;
    console.log(`❌ VULNERABLE [${name}]: ${vulns.map(r=>r.source).join(', ')}`);
  } else {
    pass++;
    console.log(`✅ SAFE [${name}]`);
  }
});

console.log("\n--- sanitizeHref Tests ---");
hrefTests.forEach(([input, expected, type]) => {
  const result = sanitizeHref(input);
  const ok = result === expected;
  if(ok){ pass++; console.log(`✅ ${type} "${input.slice(0,40)}"`); }
  else  { fail++; console.log(`❌ FAIL "${input}" expected "${expected}" got "${result}"`); }
});

console.log(`\n=== Results: ${pass} passed, ${fail} failed ===`);
if(fail === 0) console.log("✅ ALL TESTS PASSED");
else { console.log("❌ FAILURES DETECTED"); process.exit(1); }
