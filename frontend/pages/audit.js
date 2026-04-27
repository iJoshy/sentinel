import { RedirectToSignIn, SignedIn, SignedOut, useAuth } from "@clerk/nextjs";
import { useRouter } from "next/router";
import { useCallback, useEffect, useState } from "react";

import AppShell from "../components/AppShell";
import AuditTrailView from "../components/AuditTrailView";
import { SkeletonRect, SkeletonText, SkeletonTitle } from "../components/Skeleton";
import { downloadAuditPdf, downloadJobExport, fetchJobWorkflow, fetchJobs } from "../lib/api";
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

function AuditContent({ tokenProvider = null }) {
  const router = useRouter();
  const [jobRows, setJobRows] = useState([]);
  const [loadingJobs, setLoadingJobs] = useState(false);
  const [selectedJobId, setSelectedJobId] = useState("");
  const [manualId, setManualId] = useState("");
  const [workflow, setWorkflow] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

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

  const loadWorkflow = useCallback(
    async (id) => {
      if (!id) {
        setWorkflow(null);
        return;
      }
      setLoading(true);
      setErr("");
      setWorkflow(null);
      try {
        const token = tokenProvider ? await tokenProvider() : null;
        const w = await fetchJobWorkflow(id, token);
        setWorkflow(w);
      } catch (e) {
        setErr(e.message || "Failed to load workflow");
      } finally {
        setLoading(false);
      }
    },
    [tokenProvider],
  );

  useEffect(() => {
    loadJobs();
  }, [loadJobs]);

  useEffect(() => {
    if (!router.isReady) return;
    const j = router.query.job;
    if (typeof j === "string" && j.trim() && j.trim() !== selectedJobId) {
      const id = j.trim();
      setSelectedJobId(id);
      setManualId(id);
    }
  }, [router.isReady, router.query.job, selectedJobId]);

  useEffect(() => {
    if (selectedJobId) {
      void loadWorkflow(selectedJobId);
    } else {
      setWorkflow(null);
    }
  }, [selectedJobId, loadWorkflow]);

  function applyJobId(id) {
    const trimmed = (id || "").trim();
    setSelectedJobId(trimmed);
    setManualId(trimmed);
    if (router.isReady) {
      const q = trimmed ? { job: trimmed } : {};
      void router.replace({ pathname: "/audit", query: q }, undefined, { shallow: true });
    }
  }

  function onSelectRun(e) {
    const v = e.target.value;
    setManualId(v);
    applyJobId(v);
  }

  function onLoadManual() {
    applyJobId(manualId);
  }

  async function onDownloadJson() {
    if (!selectedJobId) return;
    const token = tokenProvider ? await tokenProvider() : null;
    await downloadJobExport(selectedJobId, "json", token);
  }

  async function onDownloadAuditPdf() {
    if (!selectedJobId) return;
    setErr("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      await downloadAuditPdf(selectedJobId, token);
    } catch (e) {
      setErr(e?.message || "Failed to download audit PDF");
    }
  }

  return (
    <AppShell activeHref="/audit">
      <header className="page-header">
        <div>
          <p className="eyebrow">Read-only</p>
          <h1 className="page-title">Audit</h1>
          <p className="page-sub muted">Select a run to review the full trail: pipeline, analysis, clarifications, checklist, chat, and PIR.</p>
        </div>
        <div className="page-header-actions" />
      </header>

      <div className="card-elevated dashboard-filter-bar" style={{ marginBottom: 24, padding: "16px 20px" }}>
        <div className="row gap" style={{ flexWrap: "wrap", alignItems: "flex-end", gap: 12 }}>
          <label className="dashboard-filter-label" style={{ flex: "1 1 280px", minWidth: 0, margin: 0 }}>
            <span className="muted small" style={{ display: "block", marginBottom: 6 }}>
              Run
            </span>
            {loadingJobs ? (
              <SkeletonRect height={38} style={{ width: "100%", borderRadius: 8 }} />
            ) : (
              <select
                className="input"
                value={selectedJobId}
                onChange={onSelectRun}
                style={{ width: "100%", marginTop: 0 }}
              >
                <option value="">{jobRows.length ? "Choose a run…" : "No runs yet — use Analyze first"}</option>
                {jobRows.map((row) => (
                  <option key={row.job_id} value={row.job_id}>
                    {runLabel(row)}
                  </option>
                ))}
              </select>
            )}
          </label>
          <div style={{ flex: "1 1 200px" }}>
            <span className="muted small" style={{ display: "block", marginBottom: 6 }}>
              Or job ID
            </span>
            <div className="row gap" style={{ flexWrap: "nowrap", alignItems: "stretch" }}>
              <input
                className="input"
                value={manualId}
                onChange={(e) => setManualId(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") onLoadManual();
                }}
                placeholder="UUID"
                style={{ flex: 1, margin: 0, fontFamily: "ui-monospace, monospace", fontSize: 13 }}
              />
              <button type="button" className="btn btn-muted" onClick={onLoadManual}>
                Load
              </button>
            </div>
          </div>
          <button type="button" className="btn btn-muted" onClick={loadJobs}>
            Refresh list
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onDownloadJson}
            disabled={!selectedJobId || loading}
          >
            Download JSON
          </button>
          <button
            type="button"
            className="btn"
            onClick={onDownloadAuditPdf}
            disabled={!selectedJobId || loading}
            title="Traditional black-on-white audit report (Times, numbered sections)"
          >
            Export PDF (Classic)
          </button>
        </div>
        {selectedJobId ? (
          <p className="muted small" style={{ margin: "12px 0 0" }}>
            Share:{" "}
            <a className="link-subtle" href={`/audit?job=${encodeURIComponent(selectedJobId)}`}>
              /audit?job={selectedJobId.slice(0, 8)}…
            </a>
          </p>
        ) : null}
        {loading ? (
          <div style={{ margin: "12px 0 0" }}>
            <SkeletonText lines={1} style={{ width: "120px", height: 14 }} />
          </div>
        ) : null}
      </div>

      {err ? <p className="error compact">{err}</p> : null}
      {!selectedJobId && !loading ? (
        <p className="muted small" style={{ marginBottom: 24 }}>
          Pick a <strong>run</strong> or enter a <strong>job ID</strong> to load the audit trail. Create runs on{" "}
          <a className="link-subtle" href="/analyze">
            Analyze
          </a>{" "}
          or the{" "}
          <a className="link-subtle" href="/dashboard">
            Dashboard
          </a>
          .
        </p>
      ) : null}

      {loading ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div className="card-elevated" style={{ padding: "24px" }}>
            <SkeletonTitle />
            <SkeletonText lines={6} />
          </div>
          <div className="card-elevated" style={{ padding: "24px" }}>
            <SkeletonTitle />
            <SkeletonRect height={120} />
          </div>
          <div className="card-elevated" style={{ padding: "24px" }}>
            <SkeletonTitle />
            <SkeletonText lines={10} />
          </div>
        </div>
      ) : selectedJobId && !err && workflow ? (
        <AuditTrailView workflow={workflow} />
      ) : null}
    </AppShell>
  );
}

function AuthenticatedAudit() {
  const { getToken } = useAuth();
  return <AuditContent tokenProvider={getToken} />;
}

export default function Audit() {
  if (!clerkEnabled) {
    return <AuditContent />;
  }
  return (
    <>
      <SignedIn>
        <AuthenticatedAudit />
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  );
}
