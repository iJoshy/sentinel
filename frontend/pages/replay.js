import { RedirectToSignIn, SignedIn, SignedOut, useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useState } from "react";

import AppShell from "../components/AppShell";
import ReplayPlayer from "../components/ReplayPlayer";
import { SkeletonRect, SkeletonText, SkeletonTitle } from "../components/Skeleton";
import { explainReplayFrame, fetchJobs, fetchReplay } from "../lib/api";
import { isClerkEnabled } from "../lib/clerk";

const clerkEnabled = isClerkEnabled();

function runLabel(row) {
  const title = row.title || "Untitled";
  const when = row.created_at ? new Date(row.created_at).toLocaleString() : "—";
  const st =
    row.status === "completed"
      ? "Complete"
      : row.status === "failed"
        ? "Failed"
        : row.status === "processing"
          ? "Running"
          : "Pending";
  return `${title} — ${when} — ${st}`;
}

function ReplayContent({ tokenProvider = null }) {
  const [jobRows, setJobRows] = useState([]);
  const [loadingJobs, setLoadingJobs] = useState(false);
  const [jobId, setJobId] = useState("");
  const [replay, setReplay] = useState(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);
  const [explainingIndex, setExplainingIndex] = useState(null);
  const [explainByIndex, setExplainByIndex] = useState({});

  const loadJobs = useCallback(async () => {
    setLoadingJobs(true);
    setErr("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const rows = await fetchJobs(50, token);
      setJobRows(rows);
    } catch (e) {
      setErr(e.message || "Failed to load job list");
    } finally {
      setLoadingJobs(false);
    }
  }, [tokenProvider]);

  useEffect(() => {
    loadJobs();
  }, [loadJobs]);

  const completed = jobRows.filter((r) => r.status === "completed");

  const loadReplay = useCallback(async (id) => {
    if (!id) {
      setReplay(null);
      return;
    }
    setLoading(true);
    setErr("");
    setExplainByIndex({});
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const data = await fetchReplay(id, token);
      setReplay(data);
    } catch (e) {
      setErr(e.message || "Failed to load replay");
      setReplay(null);
    } finally {
      setLoading(false);
    }
  }, [tokenProvider]);

  async function onExplainFrame(frameIndex) {
    if (!jobId) return;
    setExplainingIndex(frameIndex);
    setErr("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const res = await explainReplayFrame(jobId, frameIndex, token);
      setExplainByIndex((prev) => ({ ...prev, [frameIndex]: res }));
    } catch (e) {
      setErr(e.message || "Failed to explain replay frame");
    } finally {
      setExplainingIndex(null);
    }
  }

  return (
    <AppShell activeHref="/replay">
      <header className="page-header">
        <div>
          <p className="eyebrow">Playback</p>
          <h1 className="page-title">Incident Replay</h1>
          <p className="page-sub muted">
            Re-run the pipeline timeline for one completed run, step by step.
          </p>
        </div>
      </header>

      <div className="card-elevated dashboard-filter-bar" style={{ marginBottom: 20, padding: "16px 20px" }}>
        <div className="row gap" style={{ flexWrap: "wrap", alignItems: "flex-end", gap: 12 }}>
          <label className="dashboard-filter-label" style={{ flex: "1 1 340px", margin: 0 }}>
            <span className="muted small" style={{ display: "block", marginBottom: 6 }}>Run</span>
            {loadingJobs ? (
              <SkeletonRect height={38} style={{ width: "100%", borderRadius: 8 }} />
            ) : (
              <select
                className="input"
                value={jobId}
                onChange={(e) => {
                  const v = e.target.value;
                  setJobId(v);
                  void loadReplay(v);
                }}
                style={{ width: "100%", marginTop: 0 }}
              >
                <option value="">{completed.length ? "Choose a completed run…" : "No completed runs yet"}</option>
                {completed.map((row) => (
                  <option key={row.job_id} value={row.job_id}>
                    {runLabel(row)}
                  </option>
                ))}
              </select>
            )}
          </label>

          <button type="button" className="btn btn-muted" onClick={loadJobs}>
            Refresh list
          </button>
        </div>
      </div>

      {err ? <p className="error compact">{err}</p> : null}
      
      {loading ? (
        <div className="card-elevated" style={{ padding: "24px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 20 }}>
            <SkeletonTitle />
            <div className="skeleton" style={{ width: 100, height: 32, borderRadius: 20 }} />
          </div>
          <SkeletonRect height={240} style={{ marginBottom: 20 }} />
          <div style={{ display: "flex", gap: 12 }}>
            <div className="skeleton" style={{ width: 80, height: 32, borderRadius: 6 }} />
            <div className="skeleton" style={{ flex: 1, height: 32, borderRadius: 6 }} />
          </div>
          <div style={{ marginTop: 24 }}>
            <SkeletonText lines={5} />
          </div>
        </div>
      ) : replay ? (
        <ReplayPlayer
          replay={replay}
          onExplainFrame={onExplainFrame}
          explainResultByIndex={explainByIndex}
          explainingIndex={explainingIndex}
        />
      ) : null}
    </AppShell>
  );
}

function AuthenticatedReplay() {
  const { getToken } = useAuth();
  return <ReplayContent tokenProvider={getToken} />;
}

export default function ReplayPage() {
  if (!clerkEnabled) {
    return <ReplayContent />;
  }
  return (
    <>
      <SignedIn>
        <AuthenticatedReplay />
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  );
}