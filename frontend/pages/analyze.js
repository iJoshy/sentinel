import { RedirectToSignIn, SignedIn, SignedOut, useAuth, useUser } from "@clerk/nextjs";
import { useEffect, useRef, useState } from "react";

import AnalysisReport from "../components/AnalysisReport";
import AppShell from "../components/AppShell";
import IncidentInput from "../components/IncidentInput";
import InvestigationStreamPanel from "../components/InvestigationStreamPanel";
import RunTimeline from "../components/RunTimeline";
import { useAnalyzeSession } from "../context/AnalyzeSessionContext";
import {
  createIncident,
  fetchJob,
  pollJobUntilDone,
  streamJobUntilTerminal,
  uploadIncidentsZip,
} from "../lib/api";
import { isClerkEnabled } from "../lib/clerk";

const clerkEnabled = isClerkEnabled();

async function runIncidentAnalysis(payload, getToken, onLiveEvents) {
  const token = clerkEnabled && getToken ? await getToken() : null;
  const created = await createIncident(payload, token);

  const collected = [];
  let finalJob = null;
  try {
    finalJob = await streamJobUntilTerminal(created.job_id, token, {
      onEvent: (p) => {
        if (p.event) {
          collected.push(p.event);
          if (onLiveEvents) onLiveEvents([...collected]);
        }
        if (p.terminal && p.job) {
          finalJob = p.job;
        }
      },
    });
  } catch {
    /* fall back to polling */
  }

  if (!finalJob) {
    finalJob = await pollJobUntilDone(created.job_id, token);
  }

  const events =
    finalJob?.pipeline_events?.length >= collected.length ? finalJob.pipeline_events : collected.length ? collected : finalJob?.pipeline_events || [];

  return { job: finalJob, events };
}

function HomeContent({ getToken = null, userProfile = null }) {
  const [loading, setLoading] = useState(false);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [bulkResults, setBulkResults] = useState(null);
  /** Bumped on each new bulk upload or manual analyze — cancels stale “follow first ZIP job” work. */
  const bulkFollowSessionRef = useRef(0);
  /** Job IDs from the latest bulk upload — drives polling until all terminal. */
  const [bulkPollIds, setBulkPollIds] = useState(null);
  /** job_id → live row from GET /api/jobs/{id} */
  const [bulkJobStatuses, setBulkJobStatuses] = useState({});
  /** True while we stream/poll the first ZIP job to fill the right-hand timeline. */
  const [bulkFollowPanelLoading, setBulkFollowPanelLoading] = useState(false);
  /** True while loading another bulk job into the report / timeline (GET /api/jobs/:id). */
  const [bulkJobSwitchLoading, setBulkJobSwitchLoading] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const {
    result,
    setResult,
    pipelineEvents,
    setPipelineEvents,
    error,
    setError,
    draft,
    updateDraft,
    clearAnalysis,
  } = useAnalyzeSession();

  async function showBulkJobInPanel(jobId) {
    setBulkJobSwitchLoading(true);
    setError("");
    try {
      const token = clerkEnabled && getToken ? await getToken() : null;
      const job = await fetchJob(jobId, token);
      setResult(job);
      setPipelineEvents(job.pipeline_events || []);
    } catch (e) {
      setError(e.message || "Could not load that job");
    } finally {
      setBulkJobSwitchLoading(false);
    }
  }

  async function onAnalyze(payload) {
    bulkFollowSessionRef.current += 1;
    setLoading(true);
    setError("");
    setSubmitError("");
    setBulkJobSwitchLoading(false);
    setBulkResults(null);
    setBulkPollIds(null);
    setBulkJobStatuses({});
    updateDraft({ title: payload.title, source: payload.source, text: payload.text });
    setResult(null);
    setPipelineEvents([]);
    try {
      const { job, events } = await runIncidentAnalysis(payload, getToken, (live) => setPipelineEvents(live));
      setResult(job);
      setPipelineEvents(events);
    } catch (err) {
      if (err.status === 422) {
        // Input validation failure — show inside the form, not as a general error.
        setSubmitError(err.message || "Input validation failed. Check your log data and try again.");
      } else {
        setError(err.message || "Failed to analyze incident");
      }
    } finally {
      setLoading(false);
    }
  }

  async function onBulkUpload(file) {
    bulkFollowSessionRef.current += 1;
    const uploadSession = bulkFollowSessionRef.current;
    setBulkLoading(true);
    setError("");
    setSubmitError("");
    setResult(null);
    setPipelineEvents([]);
    setBulkJobSwitchLoading(false);
    setBulkResults(null);
    setBulkPollIds(null);
    setBulkJobStatuses({});
    // Bulk ZIP does not use the paste box; clear stale text from a prior manual analyze.
    updateDraft({ text: "", source: "upload" });
    try {
      const token = clerkEnabled && getToken ? await getToken() : null;
      const result = await uploadIncidentsZip(
        file,
        { source: "upload", titlePrefix: draft.title || "" },
        token,
      );
      if (bulkFollowSessionRef.current !== uploadSession) {
        return;
      }
      const created = result.created || [];
      setBulkResults({
        fileName: file.name,
        created,
        skipped: result.skipped || [],
      });
      setBulkPollIds(created.map((c) => c.job_id));

      const firstJobId = created[0]?.job_id;
      if (firstJobId) {
        void (async () => {
          setBulkFollowPanelLoading(true);
          try {
            const followToken = clerkEnabled && getToken ? await getToken() : null;
            const collected = [];
            let finalJob = null;
            try {
              finalJob = await streamJobUntilTerminal(firstJobId, followToken, {
                onEvent: (p) => {
                  if (bulkFollowSessionRef.current !== uploadSession) return;
                  if (p.event) {
                    collected.push(p.event);
                    setPipelineEvents([...collected]);
                  }
                  if (p.terminal && p.job) {
                    finalJob = p.job;
                  }
                },
              });
            } catch {
              /* fall through to polling */
            }
            if (bulkFollowSessionRef.current !== uploadSession) return;
            if (!finalJob || (finalJob.status !== "completed" && finalJob.status !== "failed")) {
              try {
                finalJob = await pollJobUntilDone(firstJobId, followToken, {
                  intervalMs: 2000,
                  maxWaitMs: 900_000,
                });
              } catch (e) {
                if (bulkFollowSessionRef.current === uploadSession) {
                  setError((prev) => prev || e.message || "First ZIP job did not finish in time.");
                }
                return;
              }
            }
            if (bulkFollowSessionRef.current !== uploadSession) return;
            const events =
              finalJob?.pipeline_events?.length >= collected.length
                ? finalJob.pipeline_events
                : collected.length
                  ? collected
                  : finalJob?.pipeline_events || [];
            setResult(finalJob);
            setPipelineEvents(events);
          } finally {
            setBulkFollowPanelLoading(false);
          }
        })();
      }
    } catch (err) {
      if (err.status === 400) {
        setSubmitError(err.message || "Bulk ZIP was rejected.");
      } else {
        setError(err.message || "Bulk upload failed");
      }
    } finally {
      setBulkLoading(false);
    }
  }

  useEffect(() => {
    if (!bulkPollIds?.length) return undefined;

    const jobIds = bulkPollIds;
    let cancelled = false;
    let timeoutId;

    async function pollLoop() {
      if (cancelled) return;
      const token = clerkEnabled && getToken ? await getToken() : null;
      const updates = {};
      await Promise.all(
        jobIds.map(async (jobId) => {
          try {
            const j = await fetchJob(jobId, token);
            updates[jobId] = {
              status: j.status || "unknown",
              current_stage: j.current_stage || "",
              error: j.error || "",
            };
          } catch {
            updates[jobId] = { status: "unknown", current_stage: "", error: "Could not fetch status" };
          }
        }),
      );
      if (cancelled) return;
      setBulkJobStatuses((prev) => ({ ...prev, ...updates }));

      const terminal = new Set(["completed", "failed"]);
      const allDone = jobIds.every((id) => terminal.has(updates[id]?.status));
      if (allDone) return;
      timeoutId = setTimeout(pollLoop, 2500);
    }

    pollLoop();

    return () => {
      cancelled = true;
      if (timeoutId) clearTimeout(timeoutId);
    };
  }, [(bulkPollIds || []).join("|"), clerkEnabled, getToken]);

  const canClear = !!(
    draft.text.trim()
    || result
    || pipelineEvents.length
    || error
    || bulkResults
  );

  return (
    <AppShell activeHref="/analyze">
      <header className="page-header">
        <div>
          <p className="eyebrow">Incident intelligence</p>
          <h1 className="page-title">Command center</h1>
          <p className="page-sub muted">Submit logs, then follow the live pipeline. Charts and file export are on the Dashboard.</p>
        </div>
        <div className="page-header-actions">
          {!clerkEnabled ? <p className="muted small">Local mode: auth disabled.</p> : null}
        </div>
      </header>

      <div className="analyze-grid">
        <div className="analyze-col analyze-col-input">
          <IncidentInput
            onAnalyze={onAnalyze}
            onBulkUpload={onBulkUpload}
            loading={loading}
            bulkLoading={bulkLoading}
            draft={draft}
            onDraftChange={(changes) => {
              setSubmitError("");
              if (changes.source === "upload" && changes.text !== undefined) {
                setResult(null);
                setPipelineEvents([]);
              }
              updateDraft(changes);
            }}
            onClear={() => {
              bulkFollowSessionRef.current += 1;
              setBulkFollowPanelLoading(false);
              clearAnalysis();
              setSubmitError("");
              setBulkResults(null);
              setBulkPollIds(null);
              setBulkJobStatuses({});
              setBulkJobSwitchLoading(false);
            }}
            canClear={canClear}
            submitError={submitError}
          />
          {bulkResults ? (
            <div className="card" style={{ marginTop: 12 }}>
              <h3 style={{ marginTop: 0, marginBottom: 10 }}>Bulk Upload Results</h3>
              <p className="muted small" style={{ marginTop: 0 }}>
                File: {bulkResults.fileName}
              </p>
              <p className="muted small" style={{ marginTop: 6 }}>
                Remediation TODO and Immediate Checks load for <strong>one job at a time</strong> (same job you pick on the{" "}
                <a className="link-subtle" href="/audit">Audit</a> page). Use <strong>View</strong> to switch ZIP files after each run finishes.
              </p>
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
                  <thead>
                    <tr>
                      <th style={{ textAlign: "left", padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>Log File</th>
                      <th style={{ textAlign: "left", padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>Job</th>
                      <th style={{ textAlign: "left", padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>Status</th>
                      <th style={{ textAlign: "left", padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>Report</th>
                    </tr>
                  </thead>
                  <tbody>
                    {bulkResults.created.map((item) => {
                      const st = bulkJobStatuses[item.job_id];
                      const status = st?.status || "pending";
                      const stage = st?.current_stage;
                      const err = st?.error;
                      const statusCell = err && status === "failed"
                        ? `${status}: ${err}`
                        : stage && status === "processing"
                          ? `${status} (${stage})`
                          : stage
                            ? `${status} · ${stage}`
                            : status;
                      const canView = status === "completed" || status === "failed";
                      const isShown = result?.job_id === item.job_id;
                      return (
                      <tr
                        key={item.job_id}
                        style={isShown ? { background: "var(--surface-2, rgba(0,0,0,0.04))" } : undefined}
                      >
                        <td style={{ padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>{item.file}</td>
                        <td style={{ padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>
                          <a className="link-subtle" href={`/dashboard?job=${encodeURIComponent(item.job_id)}`}>
                            {item.job_id.slice(0, 10)}...
                          </a>
                        </td>
                        <td style={{ padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>{statusCell}</td>
                        <td style={{ padding: "8px 6px", borderBottom: "1px solid var(--border)", whiteSpace: "nowrap" }}>
                          {canView ? (
                            <button
                              type="button"
                              className="btn btn-muted"
                              style={{ fontSize: 12, padding: "4px 10px" }}
                              disabled={bulkJobSwitchLoading}
                              onClick={() => void showBulkJobInPanel(item.job_id)}
                            >
                              {isShown ? "Showing" : "View"}
                            </button>
                          ) : (
                            <span className="muted small">—</span>
                          )}
                        </td>
                      </tr>
                      );
                    })}
                    {bulkResults.skipped.map((item, idx) => (
                      <tr key={`${item.file}-${idx}`}>
                        <td style={{ padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>{item.file}</td>
                        <td style={{ padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>-</td>
                        <td style={{ padding: "8px 6px", borderBottom: "1px solid var(--border)", color: "var(--warning)" }}>
                          Skipped: {item.reason}
                        </td>
                        <td style={{ padding: "8px 6px", borderBottom: "1px solid var(--border)" }}>—</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
          {error ? <p className="error compact">{error}</p> : null}
        </div>
        <div className="analyze-col analyze-col-run">
          <RunTimeline job={result} pipelineEvents={pipelineEvents} running={loading || bulkFollowPanelLoading || bulkJobSwitchLoading} />
        </div>
      </div>

      <p className="muted small" style={{ marginTop: 8 }}>
        After a run finishes, open the{" "}
        <a className="link-subtle" href="/dashboard">
          Dashboard
        </a>{" "}
        for log charts and exports.
      </p>

      <AnalysisReport result={result} getToken={getToken} userProfile={userProfile} showExport={false} />

      <InvestigationStreamPanel
        job={result}
        getToken={getToken}
        disabled={loading || bulkFollowPanelLoading || bulkJobSwitchLoading || !result || result.status !== "completed"}
      />
    </AppShell>
  );
}

function UnauthenticatedHome() {
  return <HomeContent />;
}

function AuthenticatedHome() {
  const { getToken } = useAuth();
  const { user } = useUser();
  const userProfile = user ? {
    email: user.primaryEmailAddress?.emailAddress || "",
    name: user.fullName || user.username || "",
  } : null;
  return <HomeContent getToken={getToken} userProfile={userProfile} />;
}

export default function Home() {
  if (!clerkEnabled) {
    return <UnauthenticatedHome />;
  }

  return (
    <>
      <SignedIn>
        <AuthenticatedHome />
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  );
}
