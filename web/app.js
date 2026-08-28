const grid = document.getElementById("grid");
const detail = document.getElementById("detail");
const detailTitle = document.getElementById("detail-title");
const detailBody = document.getElementById("detail-body");
const sortBy = document.getElementById("sort-by");
const refreshBtn = document.getElementById("refresh");
const closeDetail = document.getElementById("close-detail");

let rows = [];

function scoreWidth(value) {
  return `${Math.max(0, Math.min(10, value)) * 10}%`;
}

function renderCards(data) {
  const key = sortBy.value;
  const sorted = [...data].sort((a, b) => {
    if (key === "asi") return a.asi.localeCompare(b.asi);
    if (key === "class") return a.agentic_effect_class.localeCompare(b.agentic_effect_class);
    if (key === "candidate") return b.candidate_aivss - a.candidate_aivss;
    return b.mode1_aivss - a.mode1_aivss;
  });

  grid.innerHTML = sorted
    .map((row) => {
      const overlay = row.overlay_triggered
        ? `<br><span class="overlay">AIVSS overlay: ${row.aivss_recommended_label || "—"}</span>`
        : "";
      return `
        <article class="card" data-asi="${row.asi}">
          <div class="card-head">
            <div class="asi-id">${row.asi}</div>
            <div class="class-pill class-${row.agentic_effect_class}">${row.agentic_effect_class}</div>
          </div>
          <div class="card-title">${row.name}<br><small>${row.title}</small></div>
          <div class="score-row">
            <div class="score-box">
              <div class="score-label">Mode 1 (CVSS-BTE)</div>
              <div class="score-value mode1">${row.mode1_aivss.toFixed(1)}</div>
              <div class="bar"><span style="width:${scoreWidth(row.mode1_aivss)}"></span></div>
            </div>
            <div class="score-box">
              <div class="score-label">Candidate adjusted</div>
              <div class="score-value candidate">${row.candidate_aivss.toFixed(1)}</div>
              <div class="bar"><span style="width:${scoreWidth(row.candidate_aivss)}"></span></div>
            </div>
          </div>
          <div class="timeline">
            <strong>SSVC/BOD analogy:</strong> ${row.bod_timeline_label || "—"}${overlay}
          </div>
        </article>`;
    })
    .join("");

  document.querySelectorAll(".card").forEach((card) => {
    card.addEventListener("click", () => showDetail(card.dataset.asi));
  });
}

async function loadTop10() {
  grid.innerHTML = "<p>Loading scores…</p>";
  const res = await fetch("/api/top10");
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  rows = await res.json();
  renderCards(rows);
}

async function showDetail(asi) {
  detail.classList.remove("hidden");
  detailTitle.textContent = `${asi} — full assessment`;
  detailBody.innerHTML = "<p>Loading report…</p>";
  const res = await fetch(`/api/scenario/${asi}`);
  const payload = await res.json();
  const ssvc = payload.report?.decision?.ssvc;
  detailBody.innerHTML = `
    <p><strong>Mode 1:</strong> ${payload.report.scores.mode1_interpretation.aivss}
       · <strong>Candidate:</strong> ${payload.report.scores.candidate_adjusted.aivss}
       · <strong>Class:</strong> ${payload.report.agentic_ai_profile.agentic_effect_class}</p>
    ${
      ssvc
        ? `<p><strong>SSVC decision table:</strong> <code>${ssvc.decision_table}</code>
           · outcomes <code>${ssvc.outcome_namespace}</code></p>`
        : ""
    }
    <pre>${JSON.stringify(payload.report, null, 2)}</pre>`;
}

sortBy.addEventListener("change", () => renderCards(rows));
refreshBtn.addEventListener("click", () => loadTop10().catch(showError));
closeDetail.addEventListener("click", () => detail.classList.add("hidden"));

function showError(err) {
  grid.innerHTML = `<p class="error">Failed to load: ${err.message}. Run <code>aivss-calc demo</code>.</p>`;
}

loadTop10().catch(showError);
