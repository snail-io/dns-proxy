const api = location.origin.replace(/\/$/, "");

async function req(path, opts = {}) {
  const r = await fetch(api + path, opts);
  const ct = r.headers.get("content-type") || "";
  const body = ct.includes("application/json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((body && body.error) || r.statusText);
  return body;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function modeBadge(m) {
  return `<span class="mode-badge ${m}">${m}</span>`;
}

async function refreshStatus() {
  try {
    const s = await req("/api/status");

    document.getElementById("statusBox").innerText =
      `规则 ${s.rules_loaded || 0} · 本地记录 ${s.hosts_loaded || 0} · 转发 ${s.forwards || 0} · 本地应答 ${s.local_hits || 0}`;

    document.getElementById("portsInfo").innerText =
      `DNS: ${s.dns_addr || "-"} · DoT: ${s.dot_addr || "-"} · DoH: ${s.doh_addr || "-"} · Admin: ${s.http_addr || "-"}`;
  } catch (e) {
    document.getElementById("statusBox").innerText = "状态不可用: " + e.message;
    document.getElementById("portsInfo").innerText = "端口信息加载失败";
  }
}

async function refreshRules() {
  const list = await req("/api/rules") || [];
  document.getElementById("count").innerText = "共 " + list.length;
  const tbody = document.getElementById("rulesBody");
  tbody.innerHTML = list.map(r => `
    <tr>
      <td>${r.id}</td>
      <td>${esc(r.domain)}</td>
      <td>${modeBadge(r.mode)}</td>
      <td>${esc(r.upstream)}</td>
      <td>${r.enabled ? "✓" : ""}</td>
      <td class="col-op">
        <button onclick="editRule(${r.id})">编辑</button>
        <button onclick="toggle(${r.id}, ${!r.enabled})">${r.enabled ? "禁用" : "启用"}</button>
        <button class="danger" onclick="del(${r.id})">删除</button>
      </td>
    </tr>
  `).join("");
}

function hostMatchBadge(m) {
  if (!m || m === "exact") return '<span class="mode-badge exact">exact</span>';
  return '<span class="mode-badge suffix">suffix</span>';
}

async function refreshHosts() {
  const list = await req("/api/hosts") || [];
  document.getElementById("hostsCount").innerText = "共 " + list.length;
  const tbody = document.getElementById("hostsBody");
  tbody.innerHTML = list.map(r => `
    <tr>
      <td>${r.id}</td>
      <td>${esc(r.domain)}</td>
      <td>${esc(r.type)}</td>
      <td>${hostMatchBadge(r.match_mode)}</td>
      <td>${esc(r.value)}</td>
      <td>${r.ttl ?? 300}</td>
      <td>${esc(r.comment || "")}</td>
      <td>${r.enabled ? "✓" : ""}</td>
      <td class="col-op">
        <button onclick="editHost(${r.id})">编辑</button>
        <button onclick="toggleHost(${r.id}, ${!r.enabled})">${r.enabled ? "禁用" : "启用"}</button>
        <button class="danger" onclick="delHost(${r.id})">删除</button>
      </td>
    </tr>
  `).join("");
}

async function createRule(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = {
    domain: fd.get("domain"),
    mode: fd.get("mode"),
    upstream: fd.get("upstream"),
    enabled: fd.get("enabled") === "on",
  };
  await req("/api/rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  e.target.reset();
  await refresh();
}

async function createHost(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = {
    domain: fd.get("domain"),
    type: fd.get("type"),
    match_mode: fd.get("match_mode") || "exact",
    value: fd.get("value"),
    ttl: parseInt(fd.get("ttl")) || 300,
    comment: fd.get("comment") || "",
    enabled: fd.get("enabled") === "on",
  };
  await req("/api/hosts", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  e.target.reset();
  e.target.querySelector('[name="type"]').value = "A";
  e.target.querySelector('[name="match_mode"]').value = "exact";
  e.target.querySelector('[name="ttl"]').value = "300";
  e.target.querySelector('[name="enabled"]').checked = true;
  await refresh();
}

async function toggle(id, enabled) {
  await req("/api/rules/" + id, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  await refresh();
}

async function toggleHost(id, enabled) {
  await req("/api/hosts/" + id, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled }),
  });
  await refresh();
}

async function del(id) {
  if (!confirm("确认删除规则 " + id + "?")) return;
  await req("/api/rules/" + id, { method: "DELETE" });
  await refresh();
}

async function delHost(id) {
  if (!confirm("确认删除本地记录 " + id + "?")) return;
  await req("/api/hosts/" + id, { method: "DELETE" });
  await refresh();
}

async function refresh() {
  await Promise.all([refreshRules(), refreshHosts(), refreshStatus()]);
}

document.addEventListener("DOMContentLoaded", () => {
  refresh();
  setInterval(refreshStatus, 10000);
  document.getElementById("changeAuthForm").addEventListener("submit", changeAuth);
});

function openModal(id) {
  document.getElementById(id).classList.remove("hidden");
}

function closeModal(id) {
  document.getElementById(id).classList.add("hidden");
}

async function editRule(id) {
  const rule = await req("/api/rules/" + id);
  const form = document.getElementById("editRuleForm");
  form.id.value = rule.id;
  form.domain.value = rule.domain;
  form.mode.value = rule.mode;
  form.upstream.value = rule.upstream;
  form.enabled.checked = rule.enabled;
  openModal("ruleModal");
}

async function updateRule(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const id = parseInt(fd.get("id"));
  const payload = {
    domain: fd.get("domain"),
    mode: fd.get("mode"),
    upstream: fd.get("upstream"),
    enabled: fd.get("enabled") === "on",
  };
  await req("/api/rules/" + id, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  closeModal("ruleModal");
  await refresh();
}

async function editHost(id) {
  const host = await req("/api/hosts/" + id);
  const form = document.getElementById("editHostForm");
  form.id.value = host.id;
  form.domain.value = host.domain;
  form.type.value = host.type;
  form.match_mode.value = host.match_mode || "exact";
  form.value.value = host.value;
  form.ttl.value = host.ttl || 300;
  form.comment.value = host.comment || "";
  form.enabled.checked = host.enabled;
  openModal("hostModal");
}

async function updateHost(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const id = parseInt(fd.get("id"));
  const payload = {
    domain: fd.get("domain"),
    type: fd.get("type"),
    match_mode: fd.get("match_mode"),
    value: fd.get("value"),
    ttl: parseInt(fd.get("ttl")) || 300,
    comment: fd.get("comment"),
    enabled: fd.get("enabled") === "on",
  };
  await req("/api/hosts/" + id, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  closeModal("hostModal");
  await refresh();
}

async function changeAuth(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const payload = {
    old_user: fd.get("old_user"),
    old_password: fd.get("old_password"),
    new_user: fd.get("new_user"),
    new_password: fd.get("new_password"),
  };
  try {
    await req("/api/auth", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    alert("账号密码修改成功，请重新登录");
    e.target.reset();
    location.reload();
  } catch (err) {
    alert("修改失败: " + err.message);
  }
}

function closeAuthModal() {
  document.getElementById("changeAuthForm").reset();
}
