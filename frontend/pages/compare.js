import { RedirectToSignIn, SignedIn, SignedOut, useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useState } from "react";

import AppShell from "../components/AppShell";
import { SkeletonRect, SkeletonText, SkeletonTitle } from "../components/Skeleton";
import { compareJobs, fetchJobs } from "../lib/api";
import { isClerkEnabled } from "../lib/clerk";

const clerkEnabled = isClerkEnabled();

function runLabel(row) {
  const title = row.title || "Untitled";
  const when = new Date(row.created_at).toLocaleString();
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

function CompareContent({ tokenProvider = null }) {
  const [jobRows, setJobRows] = useState([]);
  const [loadingJobs, setLoadingJobs] = useState(false);
  const [jobIdA, setJobIdA] = useState("");
  const [jobIdB, setJobIdB] = useState("");
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  const loadJobs = useCallback(async () => {
    setLoadingJobs(true);
    try {
      setErr("");
      const token = tokenProvider ? await tokenProvider() : null;
      const rows = await fetchJobs(100, token);
      setJobRows(rows);
    } catch (e) {
      setErr(e.message || "Failed to load jobs");
    } finally {
      setLoadingJobs(false);
    }
  }, [tokenProvider]);

  useEffect(() => {
    loadJobs();
  }, [loadJobs]);

  const completed = jobRows.filter((row) => row.status === "completed");

  async function onCompare() {
    if (!jobIdA || !jobIdB) {
      setErr("Choose two completed runs.");
      return;
    }
    if (jobIdA === jobIdB) {
      setErr("Pick two different job IDs.");
      return;
    }
    setLoading(true);
    setErr("");
    setResult(null);
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const data = await compareJobs(jobIdA, jobIdB, token);
      setResult(data);
    } catch (e) {
      setErr(e.message || "Compare failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <AppShell activeHref="/compare">
      <header className="page-header">
        <div>
          <p className="eyebrow">Pairwise</p>
          <h1 className="page-title">Compare incidents</h1>
          <p className="page-sub muted">
            Select two <strong>completed</strong> runs. Sentinel asks the model how similar the incidents are and
            what to do next.
          </p>
        </div>
        <div className="page-header-actions" />
      </header>

      <div className="card-elevated dashboard-filter-bar" style={{ marginBottom: 24, padding: "16px 20px" }}>
        <div className="row gap" style={{ flexWrap: "wrap", alignItems: "flex-end", gap: 12 }}>
          <label className="dashboard-filter-label" style={{ flex: "1 1 240px", minWidth: 0, margin: 0 }}>
            <span className="muted small" style={{ display: "block", marginBottom: 6 }}>
              Run A
            </span>
            {loadingJobs ? (
              <SkeletonRect height={38} style={{ width: "100%", borderRadius: 8 }} />
            ) : (
              <select
                className="input"
                value={jobIdA}
                onChange={(e) => {
                  setJobIdA(e.target.value);
                  setResult(null);
                }}
                style={{ width: "100%", marginTop: 0 }}
              >
                <option value="">
                  {completed.length ? "Choose run A…" : "No completed runs — use Analyze first"}
                </option>
                {completed.map((row) => (
                  <option key={`a-${row.job_id}`} value={row.job_id}>
                    {runLabel(row)}
                  </option>
                ))}
              </select>
            )}
          </label>

          <label className="dashboard-filter-label" style={{ flex: "1 1 240px", minWidth: 0, margin: 0 }}>
            <span className="muted small" style={{ display: "block", marginBottom: 6 }}>
              Run B
            </span>
            {loadingJobs ? (
              <SkeletonRect height={38} style={{ width: "100%", borderRadius: 8 }} />
            ) : (
              <select
                className="input"
                value={jobIdB}
                onChange={(e) => {
                  setJobIdB(e.target.value);
                  setResult(null);
                }}
                style={{ width: "100%", marginTop: 0 }}
              >
                <option value="">
                  {completed.length ? "Choose run B…" : "No completed runs — use Analyze first"}
                </option>
                {completed.map((row) => (
                  <option key={`b-${row.job_id}`} value={row.job_id}>
                    {runLabel(row)}
                  </option>
                ))}
              </select>
            )}
          </label>

          <button
            type="button"
            className="btn"
            onClick={() => void onCompare()}
            disabled={loading || !jobIdA || !jobIdB}
          >
            {loading ? "Comparing…" : "Compare"}
          </button>
          <button type="button" className="btn btn-muted" onClick={loadJobs} disabled={loading}>
            Refresh list
          </button>
        </div>
      </div>

      {err ? <p className="error compact">{err}</p> : null}

      {loading ? (
        <div className="card-elevated" style={{ padding: "20px 24px" }}>
          <SkeletonTitle />
          <div style={{ display: "flex", gap: 12, marginBottom: 16 }}>
            <div className="skeleton" style={{ width: 120, height: 16 }} />
            <div className="skeleton" style={{ width: 120, height: 16 }} />
          </div>
          <SkeletonText lines={6} />
        </div>
      ) : !completed.length && !err ? (
        <p className="muted small" style={{ marginBottom: 24 }}>
          Create <strong>completed</strong> runs on{" "}
          <a className="link-subtle" href="/analyze">
            Analyze
          </a>{" "}
          or the{" "}
          <a className="link-subtle" href="/dashboard">
            Dashboard
          </a>
          , then return here.
        </p>
      ) : null}

      {result ? (
        <div className="card-elevated" style={{ padding: "20px 24px" }}>
          <h2 className="page-title" style={{ fontSize: "1.1rem", marginBottom: 12 }}>
            Comparison result
          </h2>
          <p style={{ marginBottom: 8 }}>
            <strong>Verdict:</strong>{" "}
            {String(result.verdict || "—").replace(/_/g, " ")} · <strong>Confidence:</strong>{" "}
            {String(result.confidence || "—")}
          </p>
          {result.notes ? <p className="muted" style={{ marginBottom: 16 }}>{result.notes}</p> : null}

          {Array.isArray(result.overlapping_symptoms) && result.overlapping_symptoms.length > 0 ? (
            <div style={{ marginBottom: 16 }}>
              <h3 className="muted small" style={{ textTransform: "uppercase", letterSpacing: 0.04, margin: "0 0 6px" }}>
                Overlapping symptoms
              </h3>
              <ul>
                {result.overlapping_symptoms.map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            </div>
          ) : null}

          {Array.isArray(result.divergences) && result.divergences.length > 0 ? (
            <div style={{ marginBottom: 16 }}>
              <h3 className="muted small" style={{ textTransform: "uppercase", letterSpacing: 0.04, margin: "0 0 6px" }}>
                Divergences
              </h3>
              <ul>
                {result.divergences.map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            </div>
          ) : null}

          {Array.isArray(result.operator_next_steps) && result.operator_next_steps.length > 0 ? (
            <div>
              <h3 className="muted small" style={{ textTransform: "uppercase", letterSpacing: 0.04, margin: "0 0 6px" }}>
                Next steps
              </h3>
              <ul>
                {result.operator_next_steps.map((t, i) => (
                  <li key={i}>{t}</li>
                ))}
              </ul>
            </div>
          ) : null}

          <p className="muted small" style={{ marginTop: 16, marginBottom: 0 }}>
            {result.job_id_a} ↔ {result.job_id_b}
            {result.generated_at ? ` · ${result.generated_at}` : ""}
          </p>
        </div>
      ) : null}
    </AppShell>
  );
}

function AuthenticatedCompare() {
  const { getToken } = useAuth();
  return <CompareContent tokenProvider={getToken} />;
}

export default function Compare() {
  if (!clerkEnabled) {
    return <CompareContent />;
  }
  return (
    <>
      <SignedIn>
        <AuthenticatedCompare />
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  );
}