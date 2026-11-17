'use strict';
/* VOL.17 《把危险关进笼子》 — 六枚确定性小样
   全部判定照抄 python_sandbox.py / windows_job.py 源码常量。无随机、可重放。 */
function el(id){ return document.getElementById(id); }
function esc(s){ return String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

/* ===== 互动 01 · 威胁模型对照台 ===== */
const THREATS = [
  { code: 'import socket; s=socket.socket()', v: 'block',
    why: 'BLOCKED_RE 命中 "socket" → handle() 在 Popen 之前拒绝：「Blocked module import: socket.」' },
  { code: 'import urllib.request …', v: 'block',
    why: 'urllib 在 BLOCKED_MODULES 十二名单里（网络组）——闸前拒，进程未出生。' },
  { code: 'while True: pass', v: 'cap',
    why: '时间闸：主循环 0.1s 步进盯 deadline，默认 20s、上限 60s 必杀 → timed_out: true。' },
  { code: 'data = bytearray(600 * 1024 * 1024)', v: 'cap',
    why: 'JobMemoryLimit 512MB 是全笼合计 → 第四次大分配收 MemoryError（test_memory_allocation_over_job_limit_fails）。' },
  { code: "print('x' * 2000000)", v: 'cap',
    why: 'reader 线程边收边剪（4096 块 × 余量 4 倍），解码后再截 → stdout 恰好 6000 字符（test_output_is_bounded_while_draining）。' },
  { code: "open('C:/Windows/win.ini').read()", v: 'dis',
    why: '文件头明说「not filesystem or network isolation」——runner 不假装拦文件访问；合同是「别把不可信代码交给它」。' },
  { code: '读笼外任意路径的文件', v: 'dis',
    why: '同上：笼内进程的文件系统不受限；工作区边界由 workspace_files 的 _resolve() 把守——那是另一件工具的门卫。' },
  { code: '删掉笼内临时目录再退出', v: 'cap',
    why: '跑得掉也无妨：finally 里 shutil.rmtree(workdir) 反正会清场；目录固定住在 %TEMP%/ai-skill-sandbox/run-* 下。' },
];
const d1 = {
  seen: {},
  reset(){ this.seen = {}; el('d1-term').innerHTML = '# 点上面任意一行 —— 给出判定与源码依据';
    el('d1-block').textContent = '0'; el('d1-cap').textContent = '0'; el('d1-dis').textContent = '0'; this.paint(); },
  paint(){ el('d1-rows').innerHTML = THREATS.map((t, i) => {
    const seen = this.seen[i];
    const tag = { block: ['拦', 'block'], cap: ['限', 'cap'], dis: ['明说不防', 'disclaim'] }[t.v];
    return `<div class="gate-card" style="display:flex;gap:10px;align-items:center;cursor:pointer;${seen ? 'border-color:var(--steel)' : ''}" onclick="d1.pick(${i})">
      <span class="verdict ${tag[1]}">${tag[0]}</span>
      <code style="flex:1;background:var(--paper-deep);border:none;padding:2px 8px;font-size:12px">${esc(t.code)}</code>
      ${seen ? '<span style="font-family:var(--mono);font-size:10px;color:var(--steel)">已核对</span>' : ''}</div>`; }).join(''); },
  pick(i){ const t = THREATS[i]; this.seen[i] = true;
    el('d1-term').innerHTML = `<span class="k">${esc(t.code)}</span>\n→ ${esc(t.why)}`;
    const ks = Object.keys(this.seen).map(Number);
    el('d1-block').textContent = ks.filter(k => THREATS[k].v === 'block').length;
    el('d1-cap').textContent = ks.filter(k => THREATS[k].v === 'cap').length;
    el('d1-dis').textContent = ks.filter(k => THREATS[k].v === 'dis').length;
    this.paint(); }
};
/* ===== 互动 02 · 分层闸门 ===== */
const d2 = {
  reset(){ el('d2-term').innerHTML = '# 点一段代码 —— 看它在哪一层停住';
    el('d2-layer').textContent = '—'; el('d2-born').textContent = '—'; el('d2-ms').textContent = '—'; },
  log(line, cls){ el('d2-term').insertAdjacentHTML('beforeend', `\n<span class="${cls || ''}">${esc(line)}</span>`); },
  fire(op){ const T = el('d2-term'); T.innerHTML = '';
    const cases = {
      long: { layer: '① 长度闸（闸前拒）', born: '否 · Popen 之前', ms: '≈ 0ms',
        lines: [['handle({code: 9,000 字符…})', ''], ['len(code) > MAX_CODE_CHARS(8000)', 'k'], ['return {"ok": false, "error": "Code exceeds 8000 characters."}', 'e'],
                ['# 进程从未创建 —— 闸前拒', 'c']] },
      import_: { layer: '② import 闸（闸前拒）', born: '否 · Popen 之前', ms: '≈ 0ms',
        lines: [['handle({code: "import socket…"})', ''], ['BLOCKED_RE.search → 命中 "socket"', 'k'],
                ['return {"ok": false, "error": "Blocked module import: socket…"}', 'e'], ['# 五条上限里最快的一层', 'c']] },
      timeout: { layer: '④ 时间闸（笼内限）', born: '是', ms: '1.0s 后处决',
        lines: [['Popen(python -I -u) → job.attach() → stdin 收码', ''], ['0.1s × 10 步进盯 deadline', ''],
                ['remaining <= 0 → timed_out = True', 'k'], ['job.close() → TerminateJobObject 全家处决', 'e'],
                ['stderr = "Execution timed out after 1s and was killed."', 'c']] },
      output: { layer: 'reader 线程（笼内限）', born: '是', ms: '≈ 0.4s',
        lines: [['print("x" * 2000000) → 管道灌入 2,000,000 字节', ''], ['reader: 4096 块 × 余量 MAX_OUTPUT_CHARS×4 封顶', ''],
                ['decode → [:6000]', 'k'], ['stdout 恰好 6,000 字符 · returncode 0 · ok:true', 'c']] },
      memory: { layer: '③ Job 内存（内核围栏）', born: '是', ms: '≈ 0.3s',
        lines: [['data = bytearray(600 * 1024 * 1024)', ''], ['JobMemoryLimit 512MB · 全笼合计 → 分配失败', 'k'],
                ['stderr 含 "MemoryError" · ok:false', 'e'], ['# test_memory_allocation_over_job_limit_fails 同款', 'c']] },
      ok: { layer: '通过（全部六层）', born: '是', ms: '≈ 30ms',
        lines: [['print(2**10)', ''], ['stdout = "1024" · returncode 0', 'ok'], ['collect_artifacts() → 无产物', ''],
                ['finally: rmtree(workdir) 清场', 'c']] },
    };
    const c = cases[op === 'import' ? 'import_' : op];
    c.lines.forEach(l => this.log(l[0], l[1]));
    el('d2-layer').textContent = c.layer; el('d2-born').textContent = c.born; el('d2-ms').textContent = c.ms; }
};
/* ===== 互动 03 · import 判定器 ===== */
const D3_RE = /(?:^|[;\s(])(?:import|from)\s+(socket|urllib|requests|http|ftplib|telnetlib|subprocess|multiprocessing|ctypes|asyncio|shutil|signal)(?:[\s.,;(]|$)/;
const D3_CASES = [
  { code: 'import socket', note: '黑名单正中' },
  { code: 'import socketing', note: '后缀定界符救了它：socketing 不是 socket，不拦' },
  { code: 'from http.client import client', note: 'from 句式同样命中（http）' },
  { code: 'x=1; import requests', note: '前缀定界符：分号后的 import 照样抓' },
  { code: '# import socket', note: '宁可错杀：注释里的 import 也拦——误拦只花一次重试' },
  { code: 'import json, math', note: '标准库日常成员，放行' },
];
const d3 = {
  n: 0, block: 0, over: 0,
  reset(){ this.n = 0; this.block = 0; this.over = 0;
    el('d3-term').innerHTML = '# 点病例 —— 正则判定与源码同款（JS 移植，模式串逐字一致）';
    el('d3-n').textContent = '0 / 6'; el('d3-block').textContent = '0'; el('d3-over').textContent = '0'; this.paint(); },
  paint(){ el('d3-cases').innerHTML = D3_CASES.map((c, i) => {
    const hit = D3_RE.exec(c.code); const blocked = !!hit;
    const done = i < this.n;
    return `<div class="gate-card" style="cursor:pointer;${done ? 'border-color:' + (blocked ? 'var(--red)' : 'var(--green)') : ''}" onclick="d3.pick(${i})">
      <code style="background:var(--paper-deep);border:none;padding:1px 6px;font-size:12.5px">${esc(c.code)}</code>
      <div style="margin-top:6px">${done ? `<span class="verdict ${blocked ? 'block' : 'allow'}">${blocked ? '拦 · ' + esc(hit[1]) : '放行'}</span>` : '<span style="font-family:var(--mono);font-size:11px;color:var(--faint)">病例 ' + (i + 1) + ' · 未判</span>'}</div></div>`; }).join(''); },
  pick(i){ if (i !== this.n) return; const c = D3_CASES[i]; const hit = D3_RE.exec(c.code);
    el('d3-term').insertAdjacentHTML('beforeend', `\n<span class="k">${esc(c.code)}</span> → ${hit ? `<span class="e">拦（${esc(hit[1])}）</span>` : '<span class="ok">放行</span>'} —— ${esc(c.note)}`);
    this.n++; if (hit) this.block++;
    if (i === 4 && hit) this.over++;
    el('d3-n').textContent = this.n + ' / 6'; el('d3-block').textContent = this.block; el('d3-over').textContent = this.over;
    this.paint(); }
};
/* ===== 互动 04 · 进程树围栏 ===== */
const d4 = {
  root: null, kids: [], orphans: 0, closed: false, mem: 0,
  draw(){ const row = (name, alive, note) => `${name}  [${alive ? '活 · ' + note : '死'}]`;
    let t = '';
    if (this.root !== null) {
      t = row('python -I -u (run-xxxx) pid=' + this.root, this.rootAlive, '主进程');
      this.kids.forEach((k, i) => { t += `\n  ├─ subprocess 子进程 pid=${k.pid}  [${k.alive ? '活 · sleep(30)' : '死'}]${k.orphan ? ' ← 孤儿（根已死）' : ''}`; });
      t += `\n  兜底: ${this.closed ? 'Job Object 0x2000 KILL_ON_JOB_CLOSE' : 'process.kill() 只杀根'}`;
    } else t = '# 先点「笼内进程 + 生两个孩子」';
    el('d4-tree').textContent = t;
    el('d4-root').textContent = this.root === null ? '∅' : (this.rootAlive ? 'RUNNING' : 'TERMINATED');
    el('d4-kids').textContent = this.kids.filter(k => k.alive).length + ' / ' + this.kids.length;
    el('d4-mem').textContent = this.mem + ' MB / 512 MB';
    el('d4-orphan').textContent = this.orphans + ' 个'; },
  spawn(){ if (this.closed) return; this.reset(true);
    this.root = 1000 + Math.floor(Math.random() * 9000); this.rootAlive = true; this.mem = 80;
    for (let i = 0; i < 2; i++) { this.kids.push({ pid: this.root + 100 + i, alive: true, orphan: false }); this.mem += 30; }
    this.draw(); },
  killRoot(){ if (this.root === null || !this.rootAlive) return;
    this.rootAlive = false; let freed = 80;
    this.kids.forEach(k => { if (k.alive) { k.orphan = true; this.orphans++; } });
    this.mem -= freed; this.draw(); },
  closeJob(){ if (this.root === null) return; this.closed = true; this.rootAlive = false;
    this.kids.forEach(k => { k.alive = false; if (k.orphan) { this.orphans--; } }); this.mem = 0; this.draw(); },
  reset(keep){ this.root = null; this.kids = []; this.orphans = 0; this.closed = false; this.mem = 0; this.rootAlive = false; this.draw(); }
};
/* ===== 互动 05 · 环境泄漏对照台 ===== */
const PARENT_ENV = [
  ['PATH', 'C:\Windows;C:\Windows\System32;…', false],
  ['SYSTEMROOT', 'C:\Windows', false], ['WINDIR', 'C:\Windows', false],
  ['TEMP', 'C:\\Users\\x\\AppData\\Local\\Temp', false], ['TMP', '同 TEMP', false],
  ['API_KEY_LLM', 'sk-NQR7tW9x3AbC', true], ['DATABASE_URL', 'postgres://u:p@db/…', true],
  ['GH_TOKEN', 'gho_pf0L…', true], ['AWS_SECRET_ACCESS_KEY', 'AKIA…', true],
  ['SLACK_WEBHOOK', 'https://hooks.slack.com/…', true], ['PYTHONPATH', 'D:\my-site-packages', false],
  ['PYTHONSTARTUP', 'startup.py', false],
];
const WL = ['PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP'];
const d5 = {
  paint(){ const on = el('d5-wl').checked;
    const pass = on ? PARENT_ENV.filter(([k]) => WL.includes(k)) : PARENT_ENV;
    el('d5-parent').innerHTML = PARENT_ENV.map(([k, v, secret]) =>
      `<span class="wl-key ${secret ? '' : 'off'}" title="${esc(v)}">${k}</span>`).join('');
    const redirected = on ? [['HOME', '→ run-xxxx'], ['USERPROFILE', '→ run-xxxx'], ['MPLCONFIGDIR', '→ run-xxxx']] : [];
    el('d5-cage').innerHTML = pass.map(([k, v, secret]) =>
      `<span class="wl-key" title="${esc(v)}" style="${secret ? 'border-color:var(--red);color:var(--red);background:var(--red-soft)' : ''}">${k}${secret ? ' ⚠' : ''}</span>`).join('')
      + redirected.map(([k]) => `<span class="wl-key" style="border-color:var(--steel);color:var(--steel);background:var(--steel-soft)">${k} → 笼内</span>`).join('');
    const leaks = pass.filter(([, , s]) => s).length;
    el('d5-pn').textContent = PARENT_ENV.length;
    el('d5-cn').textContent = pass.length + (on ? ' + 3 重定向' : '');
    el('d5-leak').textContent = leaks ? leaks + ' 个裸奔 ⚠' : '0';
    el('d5-leak').className = leaks ? 'badc' : 'okc';
    el('d5-home').textContent = on ? 'run-xxxx（笼内）' : '继承父进程'; },
  reset(){ el('d5-wl').checked = true; this.paint(); }
};
/* ===== 互动 06 · 产物回传流水线 ===== */
const d6 = {
  n: 0, skip: 0,
  reset(){ this.n = 0; this.skip = 0;
    el('d6-term').innerHTML = '# 跑 test_artifact_png_is_collected_as_base64 同款代码（struct+zlib 手写 1×1 PNG）';
    el('d6-n').textContent = '0'; el('d6-skip').textContent = '0'; el('d6-b64').textContent = '—'; el('d6-magic').textContent = '—'; },
  log(line, cls){ el('d6-term').insertAdjacentHTML('beforeend', `\n<span class="${cls || ''}">${esc(line)}</span>`); },
  collect(name, bytes, inList, underCap){
    this.log(`collect_artifacts(workdir) → 扫到 ${name}（${bytes} 字节）`, '');
    if (!inList) { this.skip++; this.log(`后缀不在 ARTIFACT_SUFFIXES {'.png','.jpg','.jpeg','.svg'} → 看都不看`, 'e'); }
    else if (!underCap) { this.skip++; this.log(`> MAX_ARTIFACT_BYTES(2MB) → continue 跳过`, 'e'); }
    else { this.n++; const b64 = Math.ceil(bytes * 4 / 3);
      this.log(`读成字节 → base64 → artifacts[0]: {filename:'${name}', media_type:'image/png'}`, 'ok');
      this.log(`base64 后 ≈ ${b64} 字符 · 解回首 8 字节 = \x89PNG\r\n\x1a\n`, 'ok');
      el('d6-b64').textContent = b64 + ' 字符'; el('d6-magic').textContent = String.fromCharCode(0x89) + 'PNG 完好'; el('d6-magic').className = 'okc'; }
    el('d6-n').textContent = this.n; el('d6-skip').textContent = this.skip; },
  run(){ this.log('Popen(python -I -u) → job.attach() → stdin 收码', '');
    this.log('exit 0 · duration ≈ 12ms · stdout="saved"', 'ok');
    this.log('finally: rmtree 之前 → collect_artifacts() 先扫一遍', '');
    this.collect('plot.png', 208, true, true); },
  big(){ this.collect('big.png', 3 * 1024 * 1024, true, false); },
  csv(){ this.collect('data.csv', 1540, false, true); }
};
window.addEventListener('DOMContentLoaded', () => { d1.reset(); d2.reset(); d3.reset(); d4.draw(); d5.paint(); d6.reset(); });
