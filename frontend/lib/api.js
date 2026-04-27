const CONFIGURED_BASE_URL = (process.env.NEXT_PUBLIC_API_URL || "").replace(/\/+$/, "");

function getBaseUrl() {
  if (CONFIGURED_BASE_URL) {
    return CONFIGURED_BASE_URL;
  }

  if (typeof window !== "undefined") {
    const host = window.location.hostname;
    if (host === "localhost" || host === "127.0.0.1") {
      return "http://localhost:8000";
    }
  }

  throw new Error("Sentinel API URL is not configured for this environment.");
}

async function request(path, options = {}) {
  const token = options.token;
  const baseUrl = getBaseUrl();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const res = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers,
  });

  if (!res.ok) {
    const text = await res.text();
    // FastAPI validation errors (422) return JSON with a `detail` array.
    // Extract a readable message so callers can surface it without dumping raw JSON.
    if (res.status === 422) {
      try {
        const json = JSON.parse(text);
        const msgs = (json.detail || [])
          .map((d) => {
            const raw = d.msg || d.message || JSON.stringify(d);
            // FastAPI prepends "Value error, " to every Pydantic ValueError — strip it.
            return raw.replace(/^value\s+error,\s*/i, "");
          })
          .join(" ");
        const err = new Error(msgs || "Input validation failed.");
        err.status = 422;
        throw err;
      } catch (parseErr) {
        if (parseErr.status === 422) throw parseErr;
      }
    }
    if (res.status === 401) {
      try {
        const json = JSON.parse(text);
        const d = json.detail;
        const msg = typeof d === "string" ? d : JSON.stringify(d);
        const err = new Error(msg || "Unauthorized");
        err.status = 401;
        throw err;
      } catch (parseErr) {
        if (parseErr.status === 401) throw parseErr;
      }
    }
    if (text.trim()) {
      try {
        const json = JSON.parse(text);
        if (json.detail !== undefined && json.detail !== null) {
          const d = json.detail;
          const msg =
            typeof d === "string"
              ? d
              : Array.isArray(d)
                ? d.map((x) => (typeof x === "object" && x?.msg ? x.msg : JSON.stringify(x))).join(" ")
                : String(d);
          const err = new Error(msg || `Request failed: ${res.status}`);
          err.status = res.status;
          throw err;
        }
      } catch (parseErr) {
        if (parseErr.status) throw parseErr;
      }
    }
    const err = new Error(text || `Request failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }

  // DELETE and some other routes return 204 with no body — do not call .json().
  if (res.status === 204 || res.status === 205) {
    return null;
  }
  const text = await res.text();
  if (!text.trim()) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`Invalid JSON from API (${path}): ${e.message}`);
  }
}

export async function createIncident(payload, token) {
  return request("/api/incidents", {
    method: "POST",
    body: JSON.stringify(payload),
    token,
  });
}

export async function uploadIncidentsZip(file, options = {}, token) {
  const source = options.source || "upload";
  const titlePrefix = (options.titlePrefix || "").trim();
  const baseUrl = getBaseUrl();
  const params = new URLSearchParams({ source });
  if (titlePrefix) params.set("title_prefix", titlePrefix);

  const headers = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const form = new FormData();
  form.append("archive", file, file.name || "upload.zip");

  const res = await fetch(`${baseUrl}/api/incidents/bulk-zip?${params.toString()}`, {
    method: "POST",
    headers,
    body: form,
  });

  if (!res.ok) {
    const text = await res.text();
    if (res.status === 400) {
      try {
        const json = JSON.parse(text);
        const d = json.detail;
        if (
          d
          && typeof d === "object"
          && !Array.isArray(d)
          && d.error === "bulk_zip_validation_failed"
        ) {
          const lines = [d.message || "ZIP rejected — no incidents were created."];
          if (Array.isArray(d.failures)) {
            for (const f of d.failures) {
              if (f?.file && f?.reason) lines.push(`${f.file}: ${f.reason}`);
            }
          }
          const err = new Error(lines.join("\n"));
          err.status = 400;
          throw err;
        }
      } catch (e) {
        if (e.status === 400) throw e;
      }
    }
    const err = new Error(text || `Request failed: ${res.status}`);
    err.status = res.status;
    throw err;
  }
  if (res.status === 204 || res.status === 205) {
    return null;
  }
  const okText = await res.text();
  if (!okText.trim()) {
    return null;
  }
  try {
    return JSON.parse(okText);
  } catch (e) {
    throw new Error(`Invalid JSON from API (bulk-zip): ${e.message}`);
  }
}

export async function fetchRemediationActions(jobId, token) {
  return request(`/api/jobs/${jobId}/actions`, { token });
}

export async function fetchClarificationQuestions(jobId, token) {
  return request(`/api/jobs/${jobId}/clarification-questions`, { token });
}

export async function submitClarifications(jobId, answers, token) {
  return request(`/api/jobs/${jobId}/clarify`, {
    method: "POST",
    body: JSON.stringify({ answers }),
    token,
  });
}

export async function updateRemediationAction(jobId, actionId, updates, token) {
  return request(`/api/jobs/${jobId}/actions/${actionId}`, {
    method: "PATCH",
    body: JSON.stringify(updates),
    token,
  });
}

export async function fetchIntegrations(token) {
  return request("/api/integrations", { token });
}

export async function saveIntegration(payload, token) {
  return request("/api/integrations", {
    method: "POST",
    body: JSON.stringify(payload),
    token,
  });
}

export async function deleteIntegration(integrationId, token) {
  return request(`/api/integrations/${integrationId}`, {
    method: "DELETE",
    token,
  });
}

export async function generateDigest(days, token) {
  return request("/api/reports/digest", {
    method: "POST",
    body: JSON.stringify({ days }),
    token,
  });
}

export async function downloadDigestPdf(days, token) {
  const baseUrl = getBaseUrl();
  const headers = { Accept: "application/pdf" };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${baseUrl}/api/reports/digest/export?days=${days}`, { headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Export failed: ${res.status}`);
  }
  const buf = await res.arrayBuffer();
  const blob = new Blob([buf], { type: "application/pdf" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-digest-${days}d.pdf`;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { document.body.removeChild(a); URL.revokeObjectURL(url); }, 1000);
}

export async function fetchJob(jobId, token) {
  return request(`/api/jobs/${jobId}`, { token });
}

/** GET /api/jobs/{id}/workflow — full readonly workflow snapshot (audit / review in UI). */
export async function fetchJobWorkflow(jobId, token) {
  return request(`/api/jobs/${encodeURIComponent(jobId)}/workflow`, { token });
}

/**
 * Download GET /api/jobs/{id}/audit/pdf — Classic (traditional) audit report as PDF.
 */
export async function downloadAuditPdf(jobId, token) {
  const enc = encodeURIComponent(jobId);
  const baseUrl = getBaseUrl();
  const headers = { Accept: "application/pdf" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${baseUrl}/api/jobs/${enc}/audit/pdf`, { headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Audit PDF export failed: ${res.status}`);
  }
  const buf = await res.arrayBuffer();
  const head = new Uint8Array(buf.slice(0, 5));
  const sig = String.fromCharCode(...head.slice(0, 4));
  if (sig !== "%PDF") {
    const text = new TextDecoder().decode(buf);
    throw new Error(text || "Server did not return a valid PDF.");
  }
  const blob = new Blob([buf], { type: "application/pdf" });
  const name = `sentinel-audit-${String(jobId).slice(0, 8)}.pdf`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 0);
}

export async function fetchJobs(limit = 25, token) {
  return request(`/api/jobs?limit=${encodeURIComponent(String(limit))}`, { token });
}

export async function compareJobs(jobIdA, jobIdB, token) {
  return request("/api/jobs/compare", {
    method: "POST",
    body: JSON.stringify({ job_id_a: jobIdA, job_id_b: jobIdB }),
    token,
  });
}

export async function fetchCurrentUser(token) {
  return request("/api/me", { token });
}

export async function fetchLiveBoard(token) {
  return request("/api/live/board", { token });
}

export async function updateLiveConfig(payload, token) {
  return request("/api/live/config", {
    method: "PUT",
    body: JSON.stringify(payload),
    token,
  });
}

export async function refreshLiveBoard(token) {
  return request("/api/live/refresh", {
    method: "POST",
    token,
  });
}

/**
 * Download GET /api/jobs/{id}/export?format=json|pdf as a file.
 * Pass a pre-fetched `token` when possible (e.g. from a hook) so the save dialog still opens after async work
 * in browsers that require a current user-activation.
 */
export async function downloadJobExport(jobId, format, token) {
  const enc = encodeURIComponent(jobId);
  const fmt = format === "pdf" ? "pdf" : "json";
  const accept = fmt === "pdf" ? "application/pdf" : "application/json";
  const baseUrl = getBaseUrl();
  const headers = { Accept: accept };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${baseUrl}/api/jobs/${enc}/export?format=${fmt}`, { headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Export failed: ${res.status}`);
  }
  const buf = await res.arrayBuffer();
  if (fmt === "pdf") {
    const head = new Uint8Array(buf.slice(0, 5));
    const sig = String.fromCharCode(...head.slice(0, 4));
    if (sig !== "%PDF") {
      const text = new TextDecoder().decode(buf);
      throw new Error(text || "Server did not return a valid PDF. Sign in and pick a completed run.");
    }
  }
  const mime = fmt === "pdf" ? "application/pdf" : "application/json";
  const blob = new Blob([buf], { type: mime });
  const ext = fmt === "pdf" ? "pdf" : "json";
  const name = `${fmt === "json" ? "sentinel-workflow" : "sentinel-export"}-${String(jobId).slice(0, 8)}.${ext}`;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 0);
}

/** Poll job until completed or failed (fallback if SSE unavailable). */
export async function pollJobUntilDone(jobId, token, { intervalMs = 480, maxWaitMs = 180000 } = {}) {
  const started = Date.now();
  while (Date.now() - started < maxWaitMs) {
    const job = await fetchJob(jobId, token);
    if (job.status === "completed" || job.status === "failed") {
      return job;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error("Analysis timed out. Try again or look up the job on the dashboard.");
}

/**
 * SSE over fetch (supports Authorization). Invokes onEvent for each message; resolves with final job or null.
 */
export async function streamJobUntilTerminal(jobId, token, { onEvent } = {}) {
  const baseUrl = getBaseUrl();
  const headers = {};
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${baseUrl}/api/jobs/${jobId}/stream`, { headers });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Stream failed: ${res.status}`);
  }
  const reader = res.body?.getReader();
  if (!reader) {
    throw new Error("Streaming not supported in this environment.");
  }
  const decoder = new TextDecoder();
  let buffer = "";
  let finalJob = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let sep;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const block = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      for (const line of block.split("\n")) {
        if (!line.startsWith("data: ")) continue;
        const raw = line.slice(6);
        let payload;
        try {
          payload = JSON.parse(raw);
        } catch {
          continue;
        }
        if (onEvent) onEvent(payload);
        if (payload.terminal && payload.job) {
          finalJob = payload.job;
        }
      }
    }
  }
  return finalJob;
}

// ── Follow-up reminders ────────────────────────────────────────────────────────

export async function fetchFollowUps(jobId, token) {
  return request(`/api/jobs/${encodeURIComponent(jobId)}/follow-ups`, { token });
}

export async function createFollowUp(jobId, payload, token) {
  return request(`/api/jobs/${encodeURIComponent(jobId)}/follow-ups`, {
    method: "POST",
    body: JSON.stringify(payload),
    token,
  });
}

export async function deleteFollowUp(jobId, followUpId, token) {
  const baseUrl = getBaseUrl();
  const res = await fetch(
    `${baseUrl}/api/jobs/${encodeURIComponent(jobId)}/follow-ups/${encodeURIComponent(followUpId)}`,
    {
      method: "DELETE",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    },
  );
  if (!res.ok && res.status !== 204) {
    const text = await res.text();
    throw new Error(text || `Delete failed: ${res.status}`);
  }
}

/** GET /api/jobs/{jobId}/actions/{actionId}/chat — fetch saved chat history. */
export async function fetchActionChatHistory(jobId, actionId, token) {
  const enc = encodeURIComponent(jobId);
  const aid = encodeURIComponent(actionId);
  return request(`/api/jobs/${enc}/actions/${aid}/chat`, { token });
}

/**
 * POST /api/jobs/{jobId}/actions/{actionId}/chat — stream a remediation chat reply.
 * history: array of { role: "user"|"assistant", content: string }
 */
export async function streamActionChat(jobId, actionId, message, history, token, { onChunk, onDone } = {}) {
  const baseUrl = getBaseUrl();
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const enc = encodeURIComponent(jobId);
  const aid = encodeURIComponent(actionId);
  const sanitizedHistory = (Array.isArray(history) ? history : [])
    .map((m) => ({
      role: m?.role,
      content: typeof m?.content === "string" ? m.content.trim() : "",
    }))
    .filter((m) => (m.role === "user" || m.role === "assistant") && m.content.length > 0);
  const res = await fetch(`${BASE_URL}/api/jobs/${enc}/actions/${aid}/chat`, {
    method: "POST",
    headers,
    body: JSON.stringify({ message, history: sanitizedHistory }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Chat stream failed: ${res.status}`);
  }
  const reader = res.body?.getReader();
  if (!reader) throw new Error("No stream body");
  const decoder = new TextDecoder();
  let buffer = "";
  let accumulated = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let sep;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const block = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      for (const line of block.split("\n")) {
        if (!line.startsWith("data: ")) continue;
        let payload;
        try {
          payload = JSON.parse(line.slice(6));
        } catch {
          continue;
        }
        if (payload.chunk != null) {
          accumulated += payload.chunk;
          if (onChunk) onChunk(payload.chunk, accumulated);
        }
        if (payload.done) {
          if (onDone) onDone(accumulated);
        }
      }
    }
  }
}

// ── Action findings evaluation ────────────────────────────────────────────────

export async function evaluateActionFindings(jobId, actionId, findings, token) {
  return request(
    `/api/jobs/${encodeURIComponent(jobId)}/actions/${encodeURIComponent(actionId)}/evaluate`,
    { method: "POST", body: JSON.stringify({ findings }), token },
  );
}

// ── Remediation follow-up ─────────────────────────────────────────────────────

export async function submitRemediationFollowup(jobId, additional_context, token, anchor_action_id = null) {
  return request(`/api/jobs/${encodeURIComponent(jobId)}/remediation-followup`, {
    method: "POST",
    body: JSON.stringify({ additional_context, ...(anchor_action_id ? { anchor_action_id } : {}) }),
    token,
  });
}

// ── Incident resolution & Post-Incident Review ────────────────────────────────

export async function resolveIncident(incidentId, { status = "resolved", resolution_notes = "" } = {}, token) {
  return request(`/api/incidents/${encodeURIComponent(incidentId)}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status, resolution_notes }),
    token,
  });
}

export async function generatePIR(jobId, token) {
  return request(`/api/jobs/${encodeURIComponent(jobId)}/pir`, {
    method: "POST",
    token,
  });
}

export async function fetchPIR(jobId, token) {
  return request(`/api/jobs/${encodeURIComponent(jobId)}/pir`, { token });
}

/** POST /api/stream/investigate — SSE chunks + final parse. */
export async function streamInvestigation(body, token, { onChunk, onDone } = {}) {
  const baseUrl = getBaseUrl();
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(`${baseUrl}/api/stream/investigate`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Stream failed: ${res.status}`);
  }
  const reader = res.body?.getReader();
  if (!reader) throw new Error("No stream body");
  const decoder = new TextDecoder();
  let buffer = "";
  let accumulated = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let sep;
    while ((sep = buffer.indexOf("\n\n")) !== -1) {
      const block = buffer.slice(0, sep);
      buffer = buffer.slice(sep + 2);
      for (const line of block.split("\n")) {
        if (!line.startsWith("data: ")) continue;
        let payload;
        try {
          payload = JSON.parse(line.slice(6));
        } catch {
          continue;
        }
        if (payload.chunk != null) {
          accumulated += payload.chunk;
          if (onChunk) onChunk(payload.chunk, accumulated);
        }
        if (payload.done) {
          if (onDone) onDone(payload, accumulated);
        }
      }
    }
  }
}


export async function fetchReplay(jobId, token) {
  return request(`/api/jobs/${encodeURIComponent(jobId)}/replay`, { token });
}

export async function explainReplayFrame(jobId, frameIndex, token) {
  return request(`/api/jobs/${encodeURIComponent(jobId)}/replay/explain`, {
    method: "POST",
    body: JSON.stringify({ frame_index: frameIndex }),
    token,
  });
}
