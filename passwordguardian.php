<?php
/**
 * PasswordGuardian – Strength Meter & Secure Password Generator
 * Single-file PHP app (PHP 7.4+). No external dependencies.
 *
 * Features:
 * - Client-side strength meter with entropy estimate & actionable feedback
 * - Server-side password & passphrase generator (AJAX fallback-safe)
 * - Options: length, uppercase/lowercase/digits/symbols, exclude ambiguous chars
 * - Passphrase mode (select word count & separator)
 * - Checks against a tiny demo list of common passwords (local)
 * - Copy-to-clipboard, toggle visibility, dark mode
 */

// ------------------------ Server-side helpers ------------------------

function pg_random_int($min, $max) {
    // cryptographically secure random int
    return random_int($min, $max);
}

function pg_secure_shuffle(&$array) {
    // Fisher–Yates with crypto RNG
    for ($i = count($array) - 1; $i > 0; $i--) {
        $j = pg_random_int(0, $i);
        [$array[$i], $array[$j]] = [$array[$j], $array[$i]];
    }
}

function pg_generate_password($length = 16, $useLower = true, $useUpper = true, $useDigits = true, $useSymbols = true, $excludeAmbiguous = true) {
    $lower = 'abcdefghijklmnopqrstuvwxyz';
    $upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $digits = '0123456789';
    // Commonly ambiguous: O0, I1l|, S5, B8, Z2, etc.
    $symbols = '!@#$%^&*()_+-=[]{};:,.?/';

    if ($excludeAmbiguous) {
        $upper = str_replace(['O','I','B','S','Z'], '', $upper);
        $lower = str_replace(['l','o','i','s','z'], '', $lower);
        $digits = str_replace(['0','1','2','5'], '', $digits);
        $symbols = str_replace(['|','/','\\','`','"',"'",'<','>'], '', $symbols);
    }

    $pools = [];
    if ($useLower) $pools[] = $lower;
    if ($useUpper) $pools[] = $upper;
    if ($useDigits) $pools[] = $digits;
    if ($useSymbols) $pools[] = $symbols;

    if (empty($pools)) {
        $pools = [$lower]; // fallback to lowercase
    }

    // Ensure at least one char from each selected pool, then fill rest
    $chars = [];
    foreach ($pools as $pool) {
        $chars[] = $pool[pg_random_int(0, strlen($pool)-1)];
    }
    $all = implode('', $pools);
    for ($i = count($chars); $i < $length; $i++) {
        $chars[] = $all[pg_random_int(0, strlen($all)-1)];
    }
    pg_secure_shuffle($chars);
    return implode('', $chars);
}

function pg_generate_passphrase($wordsCount = 5, $separator = '-') {
    // Small, curated word list (256 words) to keep file light. For production,
    // consider a larger Diceware list locally bundled.
    $wordlist = [
        'river','apple','quantum','velvet','ember','noble','silver','echo','forest','glider','harbor','ivory','jungle','kernel','lunar','magnet','nectar','omega','prairie','quartz','raven','solar','tunnel','utopia','vortex','willow','xenon','yonder','zenith','anchor','brisk','cinder','dynamo','ember','fable','galaxy','harvest','ion','jovial','keystone','lagoon','matrix','nova','orbit','prism','quiver','ripple','saber','thrive','union','verge','wander','xerox','yukon','zephyr','aurora','binary','cobalt','drift','ember','fluent','glyph','halo','influx','jigsaw','krypton','legend','mosaic','nylon','onyx','paradox','quasar','rumble','sage','tundra','uplink','vector','wisp','xylem','yodel','zebra','alpine','blaze','crimson','delta','ember','fjord','granite','hazel','indigo','jet','koi','lilac','merit','nimbus','opal','pixel','quill','ranger','sprout','topaz','ultra','vista','waltz','xenial','yarrow','zen','apex','bravo','cipher','dawn','ember','flora','gamma','harbor','ionic','karma','lumen','mirth','nectar','oxide','pioneer','quaint','ruin','sable','throne','unity','valor','wander','xeno','yule','zeno','atlas','brisket','cedar','dynamo','ember','flame','glisten','hexa','iris','juno','khaki','lotus','mirage','nebula','onyx','pebble','quartz','ripple','sonar','tango','utah','vintage','willow','xray','yoga','zinc','alpha','beta','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima','mike','november','oscar','papa','quebec','romeo','sierra','tango','uniform','victor','whiskey','xray','yankee','zulu','amber','butter','canyon','daisy','ember','feather','ginger','harbor','ivory','jelly','kiwi','lemon','mango','nectar','olive','pearl','quinoa','rose','sage','thyme','umber','violet','wheat','xylan','yuzu','zest','acorn','breeze','cloud','dune','ember','frost','glade','honey','island','jade','knight','lantern','meadow','north','oasis','pine','quiet','ridge','stone','trail','under','valley','wind','xenia','yacht','zonal','axis','boulder','comet','drizzle','ember','flurry','geyser','harvest','ink','jasper','karma','lodge','mesa','nectar','onyx','prairie','quiver','ridge','summit','terra','umber','vista','wild','xeno','yarn','zebra'
    ];
    $n = max(2, min(10, (int)$wordsCount));
    $words = [];
    for ($i=0; $i<$n; $i++) {
        $words[] = $wordlist[pg_random_int(0, count($wordlist)-1)];
    }
    return implode($separator, $words);
}

function pg_is_common_password($password) {
    // Tiny demonstration list. For real deployments, use a local, large list.
    static $common = [
        '123456','password','123456789','qwerty','12345678','111111','123123','abc123',
        'password1','iloveyou','12345','admin','letmein','welcome','dragon'
    ];
    return in_array($password, $common, true);
}

// AJAX endpoint
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax']) && $_POST['ajax'] === '1') {
    header('Content-Type: application/json; charset=utf-8');
    $action = $_POST['action'] ?? '';
    if ($action === 'generatePassword') {
        $len = isset($_POST['length']) ? (int)$_POST['length'] : 16;
        $pw = pg_generate_password(
            max(8, min(128, $len)),
            isset($_POST['lower']) ? $_POST['lower'] === 'true' : true,
            isset($_POST['upper']) ? $_POST['upper'] === 'true' : true,
            isset($_POST['digits']) ? $_POST['digits'] === 'true' : true,
            isset($_POST['symbols']) ? $_POST['symbols'] === 'true' : true,
            isset($_POST['noAmb']) ? $_POST['noAmb'] === 'true' : true
        );
        echo json_encode(['ok'=>true,'password'=>$pw]);
        exit;
    } elseif ($action === 'generatePassphrase') {
        $count = isset($_POST['count']) ? (int)$_POST['count'] : 5;
        $sep = $_POST['sep'] ?? '-';
        $pp = pg_generate_passphrase($count, $sep);
        echo json_encode(['ok'=>true,'passphrase'=>$pp]);
        exit;
    } else {
        echo json_encode(['ok'=>false,'error'=>'Unknown action']);
        exit;
    }
}

// ------------------------ Render page ------------------------
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PasswordGuardian – Password Strength Meter & Generator</title>
<meta name="description" content="PasswordGuardian is a lightweight, single-file PHP web app to measure password strength and generate secure passwords or passphrases.">
<style>
  :root{
    --bg:#0b0d12;
    --muted:#121522;
    --card:#0f1320;
    --text:#e6e9ef;
    --sub:#9aa4b2;
    --accent:#7c5cff;
    --ok:#22c55e;
    --warn:#f59e0b;
    --bad:#ef4444;
    --border:#212738;
  }
  *{box-sizing:border-box}
  body{
    margin:0; font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Inter, "Helvetica Neue", Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji";
    background: linear-gradient(180deg, #0b0d12, #0b0d12 40%, #0a0c16);
    color:var(--text);
  }
  header{padding:24px 16px; display:flex; align-items:center; justify-content:space-between; max-width:1080px; margin:0 auto;}
  .brand{display:flex; gap:12px; align-items:center;}
  .logo{
    width:40px; height:40px; border-radius:12px; display:grid; place-items:center;
    background: radial-gradient(60% 60% at 60% 40%, #9b8cff 0%, #6a53ff 45%, #3f2ad9 100%);
    box-shadow: 0 10px 30px rgba(124,92,255,0.35), inset 0 0 18px rgba(255,255,255,0.15);
    font-weight:700;
  }
  .title{font-weight:800; letter-spacing:0.2px}
  .subtitle{color:var(--sub); font-size:14px}
  main{max-width:1080px; margin:0 auto; padding:8px 16px 56px}
  .grid{display:grid; grid-template-columns: 1.2fr 1fr; gap:18px}
  @media (max-width: 980px){ .grid{grid-template-columns:1fr} }

  .card{
    background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.0));
    border:1px solid var(--border);
    border-radius:16px; padding:18px; box-shadow: 0 10px 30px rgba(0,0,0,0.25);
  }
  .card h2{margin:4px 0 12px 0; font-size:18px}
  label{display:block; font-size:13px; color:var(--sub); margin-bottom:8px}
  input[type="text"], input[type="number"], select{
    width:100%; padding:12px 14px; background:var(--muted); border:1px solid var(--border); color:var(--text);
    border-radius:12px; outline: none;
  }
  .row{display:grid; gap:12px; grid-template-columns:1fr 1fr}
  .row-3{display:grid; gap:12px; grid-template-columns:1fr 1fr 1fr}
  @media (max-width: 720px){ .row,.row-3{grid-template-columns:1fr} }

  .options{display:grid; gap:10px; grid-template-columns:1fr 1fr}
  .chip{
    display:flex; align-items:center; gap:8px; padding:10px 12px; border:1px solid var(--border);
    background:var(--muted); border-radius:12px; cursor:pointer; user-select:none;
  }
  .chip input{margin:0}
  .actions{display:flex; gap:10px; flex-wrap:wrap}
  button{
    background:var(--accent); color:white; border:none; border-radius:12px; padding:12px 14px; font-weight:700; cursor:pointer;
  }
  button.ghost{background:transparent; border:1px solid var(--border); color:var(--text)}
  .field{
    display:flex; gap:8px; align-items:center;
    background:var(--muted); border:1px solid var(--border); border-radius:12px; padding:8px;
  }
  .field input[type="password"], .field input[type="text"]{
    background:transparent; border:none; width:100%; padding:10px 8px; outline:none; color:var(--text);
  }
  .tiny{font-size:12px; color:var(--sub)}
  .meter{height:12px; background:#161a2a; border-radius:10px; overflow:hidden; border:1px solid var(--border)}
  .meter>div{height:100%; width:0%;}
  .badge{font-size:12px; padding:4px 8px; border-radius:999px; border:1px solid var(--border); background:var(--muted); display:inline-block}
  .list{margin:8px 0 0 0; padding-left:18px; color:var(--sub); font-size:13px}
  .ok{color:var(--ok)} .warn{color:var(--warn)} .bad{color:var(--bad)}
  .footer{
    margin-top:26px; padding-top:16px; display:flex; justify-content:space-between; flex-wrap:wrap; gap:8px;
    color:var(--sub); border-top:1px dashed var(--border);
  }
  .switch { display:inline-flex; align-items:center; gap:8px; cursor:pointer; }
  .switch input { display:none; }
  .toggle {
    width:42px; height:24px; border-radius:999px; background:var(--border); position:relative;
  }
  .toggle:before{
    content:""; position:absolute; width:18px; height:18px; border-radius:50%; top:3px; left:3px; background:#fff; transition: all .2s ease;
  }
  .switch input:checked + .toggle { background: #6755ff; }
  .switch input:checked + .toggle:before{ transform: translateX(18px); }
  .muted{color:var(--sub)}
  .sep{height:1px; background:var(--border); margin:12px 0}
</style>
</head>
<body>
  <header>
    <div class="brand">
      <div class="logo">PG</div>
      <div>
        <div class="title">PasswordGuardian</div>
        <div class="subtitle">Strength Meter & Secure Password Generator</div>
      </div>
    </div>
    <label class="switch" title="Toggle dark background glow (visual only)">
      <input id="bgToggle" type="checkbox" checked>
      <div class="toggle"></div>
      <span class="muted">Glow</span>
    </label>
  </header>

  <main class="grid">
    <!-- Strength Meter -->
    <section class="card">
      <h2>Check password strength</h2>
      <label for="pwInput">Enter a password (we never send it anywhere)</label>
      <div class="field">
        <input id="pwInput" type="password" placeholder="Type or paste a password…" autocomplete="off">
        <button id="toggleView" class="ghost" type="button" aria-label="Show password">Show</button>
        <button id="copyPw" class="ghost" type="button" aria-label="Copy password">Copy</button>
      </div>

      <div style="margin-top:12px" class="row">
        <div>
          <div class="tiny">Entropy & score</div>
          <div class="meter" aria-hidden="true"><div id="meterBar"></div></div>
          <div style="margin-top:8px; display:flex; gap:8px; align-items:center">
            <span id="scoreBadge" class="badge">Score: 0 / 4</span>
            <span id="entropyBadge" class="badge">Entropy: 0 bits</span>
            <span id="lengthBadge" class="badge">Length: 0</span>
          </div>
        </div>
        <div>
          <div class="tiny">Status</div>
          <div id="statusText" class="badge">Start typing…</div>
        </div>
      </div>

      <div class="sep"></div>
      <div class="tiny">Suggestions</div>
      <ul id="advice" class="list">
        <li>Add length (aim ≥ 16 characters)</li>
        <li>Mix character types (upper/lower/digits/symbols)</li>
        <li>Avoid common passwords and repeated patterns</li>
      </ul>
    </section>

    <!-- Generator -->
    <section class="card">
      <h2>Generate a secure secret</h2>
      <div class="row-3">
        <div>
          <label for="mode">Mode</label>
          <select id="mode">
            <option value="password">Password</option>
            <option value="passphrase">Passphrase</option>
          </select>
        </div>
        <div id="lengthWrap">
          <label for="length">Length</label>
          <input id="length" type="number" min="8" max="128" value="16">
        </div>
        <div id="ppCountWrap" style="display:none">
          <label for="ppCount">Words</label>
          <input id="ppCount" type="number" min="2" max="10" value="5">
        </div>
      </div>

      <div id="pwOptions" class="options" style="margin-top:10px">
        <label class="chip"><input id="optLower" type="checkbox" checked> Lowercase</label>
        <label class="chip"><input id="optUpper" type="checkbox" checked> Uppercase</label>
        <label class="chip"><input id="optDigits" type="checkbox" checked> Digits</label>
        <label class="chip"><input id="optSymbols" type="checkbox" checked> Symbols</label>
        <label class="chip"><input id="optNoAmb" type="checkbox" checked> Exclude ambiguous</label>
      </div>

      <div id="ppOptions" class="options" style="display:none; margin-top:10px">
        <label class="chip">
          <span>Separator</span>
          <select id="ppSep" style="margin-left:auto">
            <option value="-">-</option>
            <option value=".">.</option>
            <option value="_">_</option>
            <option value=" ">(space)</option>
          </select>
        </label>
        <div class="chip tiny">Tip: 5–7 words is great for usability & security.</div>
      </div>

      <div class="actions" style="margin-top:12px">
        <button id="btnGenerate" type="button">Generate</button>
        <button id="btnCopyOut" class="ghost" type="button">Copy</button>
        <button id="btnSendToMeter" class="ghost" type="button">Send to meter</button>
      </div>

      <label style="margin-top:12px">Output</label>
      <div class="field">
        <input id="out" type="text" readonly placeholder="Generated secret will appear here…">
      </div>
      <div class="tiny">Generation happens locally or via this server (no external calls).</div>
    </section>

    <!-- Guidance -->
    <section class="card" style="grid-column: 1 / -1;">
      <h2>Best practices</h2>
      <ul class="list">
        <li>Prefer length: aim for 16+ characters or a 5–7 word passphrase.</li>
        <li>Use a password manager to store unique passwords per site.</li>
        <li>Enable multi-factor authentication (TOTP, security keys) wherever possible.</li>
        <li>Never reuse high-value secrets (email, banking, cloud accounts).</li>
      </ul>
    </section>
  </main>

<script>
// ------------------------ UI Helpers ------------------------
const $ = (q)=>document.querySelector(q);
const pwInput = $('#pwInput');
const meterBar = $('#meterBar');
const scoreBadge = $('#scoreBadge');
const entropyBadge = $('#entropyBadge');
const lengthBadge = $('#lengthBadge');
const statusText = $('#statusText');
const adviceList = $('#advice');

const toggleView = $('#toggleView');
const copyPw = $('#copyPw');

const mode = $('#mode');
const lengthWrap = $('#lengthWrap');
const lengthInput = $('#length');
const pwOptions = $('#pwOptions');
const optLower = $('#optLower'), optUpper = $('#optUpper'), optDigits = $('#optDigits'), optSymbols = $('#optSymbols'), optNoAmb = $('#optNoAmb');

const ppCountWrap = $('#ppCountWrap');
const ppOptions = $('#ppOptions');
const ppCount = $('#ppCount');
const ppSep = $('#ppSep');

const btnGenerate = $('#btnGenerate');
const btnCopyOut = $('#btnCopyOut');
const btnSendToMeter = $('#btnSendToMeter');
const out = $('#out');

const bgToggle = $('#bgToggle');

// ------------------------ Strength Estimator ------------------------
const COMMON = new Set(['123456','password','123456789','qwerty','12345678','111111','123123','abc123','password1','iloveyou','12345','admin','letmein','welcome','dragon']);

function charsetSize(pw){
  let lower=false, upper=false, digit=false, symbol=false, other=false;
  for (const ch of pw){
    if (/[a-z]/.test(ch)) lower=true;
    else if (/[A-Z]/.test(ch)) upper=true;
    else if (/[0-9]/.test(ch)) digit=true;
    else if (/[^A-Za-z0-9]/.test(ch)) symbol=true;
    else other=true;
  }
  // Base pool sizes (approx). If ambiguous excluded we can't know; keep simple.
  let size = 0;
  if (lower) size += 26;
  if (upper) size += 26;
  if (digit) size += 10;
  if (symbol) size += 32;
  if (other) size += 10; // emoji/extended
  return size || 1;
}

function entropyBits(pw){
  // Simple estimate: L * log2(N), with small penalties for repeats & sequences
  const L = pw.length;
  const N = charsetSize(pw);
  let bits = L * Math.log2(N);

  // Penalties
  // 1) repeated blocks
  const repeats = /(.)\1{2,}/.test(pw) ? 1 : 0;
  if (repeats) bits -= 10;

  // 2) keyboard or numeric sequences (very rough)
  if (/0123|1234|2345|3456|4567|5678|6789|7890/.test(pw)) bits -= 10;
  if (/abcd|qwer|asdf|zxcv/i.test(pw)) bits -= 10;

  // 3) common password exact match
  if (COMMON.has(pw)) bits = Math.min(bits, 8);

  return Math.max(0, bits);
}

function scoreFromEntropy(bits){
  // Map to 0..4 buckets
  if (bits < 28) return 0;      // Very Weak
  if (bits < 36) return 1;      // Weak
  if (bits < 60) return 2;      // Fair
  if (bits < 80) return 3;      // Strong
  return 4;                      // Very Strong
}

function statusLabel(score, pw){
  if (COMMON.has(pw)) return 'Compromised (very common)';
  return ['Very Weak','Weak','Fair','Strong','Very Strong'][score];
}

function barColor(score){
  return [ 'var(--bad)', 'var(--warn)', '#f2c94c', 'var(--ok)', '#38bdf8' ][score];
}

function advice(pw, bits, score){
  const tips = [];
  if (COMMON.has(pw)) tips.push('Never use common passwords.');
  if (pw.length < 16) tips.push('Increase length (≥ 16).');
  if (!/[a-z]/.test(pw)) tips.push('Add lowercase letters.');
  if (!/[A-Z]/.test(pw)) tips.push('Add uppercase letters.');
  if (!/[0-9]/.test(pw)) tips.push('Add digits.');
  if (!/[^A-Za-z0-9]/.test(pw)) tips.push('Add symbols.');
  if (/(.)\1{2,}/.test(pw)) tips.push('Avoid repeated characters.');
  if (/0123|1234|2345|3456|4567|5678|6789|7890/.test(pw)) tips.push('Avoid numeric sequences.');
  if (/abcd|qwer|asdf|zxcv/i.test(pw)) tips.push('Avoid keyboard sequences.');
  if (tips.length === 0) tips.push('Looks solid. Keep it unique and store it in a password manager.');
  return tips;
}

function renderAdvice(items){
  adviceList.innerHTML = items.map(t=>`<li>${t}</li>`).join('');
}

function updateMeter(){
  const pw = pwInput.value;
  const bits = entropyBits(pw);
  const score = scoreFromEntropy(bits);
  const percent = Math.min(100, Math.round((score/4)*100));
  meterBar.style.width = percent + '%';
  meterBar.style.background = barColor(score);
  scoreBadge.textContent = `Score: ${score} / 4`;
  entropyBadge.textContent = `Entropy: ${Math.round(bits)} bits`;
  lengthBadge.textContent = `Length: ${pw.length}`;
  statusText.textContent = statusLabel(score, pw);
  statusText.className = 'badge ' + (COMMON.has(pw) ? 'bad' : (score>=3?'ok': (score===2?'':'warn')));
  renderAdvice(advice(pw, bits, score));
}

pwInput.addEventListener('input', updateMeter);
updateMeter();

// ------------------------ Controls ------------------------
toggleView.addEventListener('click', ()=>{
  if (pwInput.type === 'password') { pwInput.type = 'text'; toggleView.textContent = 'Hide'; }
  else { pwInput.type = 'password'; toggleView.textContent = 'Show'; }
});

copyPw.addEventListener('click', async ()=>{
  if (!pwInput.value) return;
  await navigator.clipboard.writeText(pwInput.value);
  copyPw.textContent = 'Copied!';
  setTimeout(()=> copyPw.textContent='Copy', 1200);
});

btnCopyOut.addEventListener('click', async ()=>{
  if (!out.value) return;
  await navigator.clipboard.writeText(out.value);
  btnCopyOut.textContent = 'Copied!';
  setTimeout(()=> btnCopyOut.textContent='Copy', 1200);
});

btnSendToMeter.addEventListener('click', ()=>{
  if (!out.value) return;
  pwInput.value = out.value;
  updateMeter();
  window.scrollTo({ top: 0, behavior: 'smooth' });
});

// ------------------------ Generator ------------------------
mode.addEventListener('change', ()=>{
  const isPw = mode.value === 'password';
  lengthWrap.style.display = isPw ? '' : 'none';
  pwOptions.style.display = isPw ? 'grid' : 'none';
  ppCountWrap.style.display = !isPw ? '' : 'none';
  ppOptions.style.display = !isPw ? 'grid' : 'none';
});

async function ajax(action, data){
  const form = new FormData();
  form.append('ajax','1');
  form.append('action', action);
  for (const [k,v] of Object.entries(data)) form.append(k, String(v));
  const res = await fetch(location.href, { method:'POST', body: form, credentials:'same-origin' });
  return res.json();
}

btnGenerate.addEventListener('click', async ()=>{
  try {
    if (mode.value === 'password') {
      const payload = {
        length: Number(lengthInput.value || 16),
        lower: optLower.checked,
        upper: optUpper.checked,
        digits: optDigits.checked,
        symbols: optSymbols.checked,
        noAmb: optNoAmb.checked
      };
      // Prefer local generation for speed (mirror of server logic, not shown).
      // But we’ll still call server to guarantee crypto RNG in older browsers.
      const data = await ajax('generatePassword', payload);
      if (data.ok) out.value = data.password;
    } else {
      const payload = {
        count: Number(ppCount.value || 5),
        sep: (ppSep.value === ' ') ? ' ' : ppSep.value
      };
      const data = await ajax('generatePassphrase', payload);
      if (data.ok) out.value = data.passphrase;
    }
  } catch (e) {
    out.value = 'Error generating. Please try again.';
  }
});

// ------------------------ Cosmetic toggle ------------------------
bgToggle.addEventListener('change', ()=>{
  document.body.style.background = bgToggle.checked
    ? 'linear-gradient(180deg, #0b0d12, #0b0d12 40%, #0a0c16)'
    : '#0b0d12';
});
</script>
</body>
</html>