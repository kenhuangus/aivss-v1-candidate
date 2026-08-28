const grid = document.getElementById("grid");
const detail = document.getElementById("detail");
const detailTitle = document.getElementById("detail-title");
const detailBody = document.getElementById("detail-body");
const sortBy = document.getElementById("sort-by");
const refreshBtn = document.getElementById("refresh");
const closeDetailBtn = document.getElementById("close-detail");

let rows = [];

function scoreWidth(value) {
  if (value == null || Number.isNaN(value)) return "0%";
  return `${Math.max(0, Math.min(10, value)) * 10}%`;
}

function formatScore(value) {
  return value == null ? "—" : Number(value).toFixed(1);
}

function overlayHtml(row) {
  const label = row.aivss_recommended_label;
  if (!label) return "";
  const escalated =
    row.escalated === true ||
    (row.aivss_recommended_timeline &&
      row.bod_timeline &&
      row.aivss_recommended_timeline !== row.bod_timeline);
  if (!escalated) return "";
  return `<span class="overlay">AIVSS overlay: ${label}</span>`;
}

function renderCards(data) {
  const key = sortBy.value;
  const sorted = [...data].sort((a, b) => {
    if (key === "asi") return a.asi.localeCompare(b.asi);
    if (key === "class") return a.agentic_effect_class.localeCompare(b.agentic_effect_class);
    if (key === "candidate") return (b.candidate_aivss ?? -1) - (a.candidate_aivss ?? -1);
    return (b.mode1_aivss ?? -1) - (a.mode1_aivss ?? -1);
  });

  grid.innerHTML = sorted
    .map((row) => {
      return `
        <article class="card" data-asi="${row.asi}">
          <div class="card-icon">${row.asi.replace("ASI", "")}</div>
          <div class="card-head">
            <div class="asi-id">${row.asi}</div>
            <div class="class-pill class-${row.agentic_effect_class}">${row.agentic_effect_class}</div>
          </div>
          <h3 class="card-name">${row.name}</h3>
          <p class="card-desc">${row.title}</p>
          <div class="score-row">
            <div class="score-box">
              <div class="score-label">Mode 1 · CVSS-BTE</div>
              <div class="score-value mode1">${formatScore(row.mode1_aivss)}</div>
              <div class="bar"><span style="width:${scoreWidth(row.mode1_aivss)}"></span></div>
            </div>
            <div class="score-box">
              <div class="score-label">Candidate adjusted</div>
              <div class="score-value candidate">${formatScore(row.candidate_aivss)}</div>
              <div class="bar"><span style="width:${scoreWidth(row.candidate_aivss)}"></span></div>
            </div>
          </div>
          <div class="timeline">
            <strong>SSVC / BOD analogy:</strong> ${row.bod_timeline_label || "—"}
            ${overlayHtml(row)}
          </div>
          <span class="btn btn-card">View full assessment</span>
        </article>`;
    })
    .join("");

  document.querySelectorAll(".card").forEach((card) => {
    card.addEventListener("click", () => showDetail(card.dataset.asi));
  });
}

async function loadTop10() {
  grid.innerHTML = "<p class='loading'>Loading OWASP Agentic Top 10 scores…</p>";
  const res = await fetch("/api/top10");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  rows = await res.json();
  if (!Array.isArray(rows) || rows.length === 0) {
    throw new Error("No ASI scenarios returned");
  }
  renderCards(rows);
}

function hideDetail() {
  detail.classList.add("hidden");
  detailBody.innerHTML = "";
  document.body.style.overflow = "";
}

async function showDetail(asi) {
  detail.classList.remove("hidden");
  document.body.style.overflow = "hidden";
  detailTitle.textContent = `${asi} — Full Assessment`;
  detailBody.innerHTML = "<p class='loading'>Loading report…</p>";

  const res = await fetch(`/api/scenario/${encodeURIComponent(asi)}`);
  if (!res.ok) {
    detailBody.innerHTML = `<p class="error">Failed to load ${asi}: HTTP ${res.status}</p>`;
    return;
  }

  const payload = await res.json();
  const report = payload.report;
  if (!report?.scores) {
    detailBody.innerHTML = `<p class="error">Invalid report payload for ${asi}.</p>`;
    return;
  }

  const mode1 = report.scores.mode1_interpretation?.aivss;
  const candidate = report.scores.candidate_adjusted?.aivss;
  const effectClass = report.agentic_ai_profile?.agentic_effect_class ?? "—";
  const ssvc = report.decision?.ssvc;
  const decision = report.decision ?? {};
  const bodLabel = decision.bod_2604_analogy_label || decision.bod_2604_label || "—";

  detailBody.innerHTML = `
    <div class="detail-meta">
      <span><strong>Mode 1:</strong> ${formatScore(mode1)}</span>
      <span><strong>Candidate:</strong> ${formatScore(candidate)}</span>
      <span><strong>Effect class:</strong> ${effectClass}</span>
      <span><strong>BOD analogy:</strong> ${bodLabel}</span>
      ${
        decision.escalated && decision.aivss_recommended_label
          ? `<span><strong>Overlay:</strong> ${decision.aivss_recommended_label}</span>`
          : ""
      }
    </div>
    ${
      ssvc
        ? `<div class="detail-ssvc">
             <strong>SSVC decision table:</strong>
             <code>${ssvc.decision_table}</code>
             · outcomes <code>${ssvc.outcome_namespace}</code>
           </div>`
        : ""
    }
    <pre>${JSON.stringify(report, null, 2)}</pre>`;
}

sortBy.addEventListener("change", () => renderCards(rows));
refreshBtn.addEventListener("click", () => loadTop10().catch(showError));
closeDetailBtn.addEventListener("click", hideDetail);
detail.addEventListener("click", (e) => {
  if (e.target === detail) hideDetail();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !detail.classList.contains("hidden")) hideDetail();
});

function showError(err) {
  grid.innerHTML = `<p class="error">Failed to load: ${err.message}. Run <code>aivss-calc demo</code>.</p>`;
}

loadTop10().catch(showError);
