// Every value from the server is shown with textContent, never parsed as HTML,
// and links stay defanged text: an email can't inject markup or a clickable link here.
"use strict";

const $ = (id) => document.getElementById(id);

function cell(row, text) {
  const td = document.createElement("td");
  td.textContent = text == null ? "" : String(text);
  row.appendChild(td);
  return td;
}

function showResult(result) {
  $("result").hidden = false;
  const verdict = $("verdict");
  verdict.textContent = result.verdict.replace("_", " ");
  verdict.className = "badge " + result.verdict;
  $("score").textContent = String(result.score);
  $("cached").textContent = result.cached ? "(from cache)" : "";

  const warning = $("warning");
  warning.hidden = result.history_status !== "unavailable";
  warning.textContent = result.history_status === "unavailable"
    ? "The scan history is unavailable, so earlier flags on this sender couldn't be checked." +
      (result.raised_from ? ` Verdict raised from ${result.raised_from.replace("_", " ")} as a precaution (${result.raise_reason}).` : "")
    : "";

  const rows = $("indicators");
  rows.replaceChildren();
  for (const indicator of result.indicators) {
    const row = document.createElement("tr");
    cell(row, indicator.id);
    cell(row, indicator.weight);
    cell(row, indicator.reason);
    cell(row, indicator.evidence.join("\n")).className = "evidence";
    rows.appendChild(row);
  }
  if (!result.indicators.length) {
    cell(rows.appendChild(document.createElement("tr")), "No indicators found.").colSpan = 4;
  }

  const notes = $("notes");
  notes.replaceChildren();
  for (const note of result.notes) {
    notes.appendChild(document.createElement("li")).textContent = note;
  }
}

async function loadHistory() {
  const rows = $("history");
  const response = await fetch("/api/history?limit=20");
  rows.replaceChildren();
  if (!response.ok) {
    cell(rows.appendChild(document.createElement("tr")), "The scan history is unavailable.").colSpan = 5;
    return;
  }
  for (const scan of (await response.json()).scans) {
    const row = document.createElement("tr");
    cell(row, scan.scanned_at.replace("T", " ").slice(0, 19));
    cell(row, scan.sender_domain ? scan.sender_domain.replaceAll(".", "[.]") : "(body only)");
    cell(row, scan.verdict.replace("_", " ")).className = "verdict-" + scan.verdict;
    cell(row, scan.score);
    cell(row, scan.signals.join(", "));
    rows.appendChild(row);
  }
}

async function scan(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  if (!form.get("email") || !form.get("email").size) {
    form.delete("email");
  }
  $("status").textContent = "Scanning…";
  try {
    const response = await fetch("/api/scan", { method: "POST", body: form });
    const body = await response.json();
    if (!response.ok) {
      $("status").textContent = body.error || `Error ${response.status}`;
      return;
    }
    $("status").textContent = "";
    showResult(body);
    await loadHistory();
  } catch (error) {
    $("status").textContent = "The request failed.";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("scan-form").addEventListener("submit", scan);
  loadHistory();
});
