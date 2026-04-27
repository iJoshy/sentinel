import { RedirectToSignIn, SignedIn, SignedOut, useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import AnalysisReport from "../components/AnalysisReport";
import AppShell from "../components/AppShell";
import LogDataCharts from "../components/LogDataCharts";
import { SkeletonRect, SkeletonText, SkeletonTitle } from "../components/Skeleton";
import { fetchJob, fetchJobs, generateDigest } from "../lib/api";
import { isClerkEnabled } from "../lib/clerk";

const clerkEnabled = isClerkEnabled();

const SEV_COLORS = {
  critical: { text: "#fb7185", border: "rgba(251,113,133,0.35)", bg: "rgba(251,113,133,0.15)" },
  high:     { text: "#fbbf24", border: "rgba(251,191,36,0.35)",  bg: "rgba(251,191,36,0.15)"  },
  medium:   { text: "#a78bfa", border: "rgba(167,139,250,0.35)", bg: "rgba(167,139,250,0.15)" },
  low:      { text: "#5eead4", border: "rgba(94,234,212,0.35)",  bg: "rgba(94,234,212,0.15)"  },
  unknown:  { text: "#8b9bb8", border: "rgba(139,155,184,0.25)", bg: "rgba(139,155,184,0.12)" },
};

function SevBadge({ sev }) {
  const c = SEV_COLORS[sev?.toLowerCase()] || SEV_COLORS.unknown;
  return (
    <span style={{
      display: "inline-block", fontSize: 10, fontWeight: 700,
      letterSpacing: "0.07em", textTransform: "uppercase",
      padding: "2px 8px", borderRadius: 6,
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
    }}>
      {sev || "unknown"}
    </span>
  );
}

function DigestStatCard({ label, value, valueColor }) {
  return (
    <div style={{
      flex: "1 1 110px", minWidth: 100,
      background: "var(--surface-2)", border: "1px solid var(--border)",
      borderRadius: "var(--radius-sm)", padding: "12px 16px",
    }}>
      <span style={{ display: "block", fontSize: 10, fontWeight: 700, color: "var(--muted)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 4 }}>
        {label}
      </span>
      <span style={{ display: "block", fontSize: 20, fontWeight: 700, color: valueColor || "var(--text)" }}>
        {value ?? "—"}
      </span>
    </div>
  );
}

const CHART_TOOLTIP_STYLE = {
  background: "var(--surface-2)", border: "1px solid var(--border)",
  borderRadius: 8, fontSize: 12, color: "var(--text)",
};

function IncidentDigest({ tokenProvider }) {
  const [days, setDays] = useState(30);
  const [digest, setDigest] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");

  const load = useCallback(async (d) => {
    setLoading(true);
    setErr("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const data = await generateDigest(d, token);
      setDigest(data);
    } catch (e) {
      setErr(e.message || "Failed to load digest");
    } finally {
      setLoading(false);
    }
  }, [tokenProvider]);

  useEffect(() => { load(days); }, [load]);

  function handleDaysChange(e) {
    const d = Number(e.target.value);
    setDays(d);
    load(d);
  }

  const sevEntries = Object.entries(digest?.severity_breakdown || {}).sort((a, b) => {
    const order = ["critical", "high", "medium", "low", "unknown"];
    return order.indexOf(a[0].toLowerCase()) - order.indexOf(b[0].toLowerCase());
  });

  const srcEntries = Object.entries(digest?.source_breakdown || {}).sort((a, b) => b[1] - a[1]);
  const maxSrc = srcEntries.length ? srcEntries[0][1] : 1;

  const daily = digest?.daily_breakdown || [];

  const xTickFormatter = (val) => {
    if (!val) return "";
    const d = new Date(val + "T00:00:00");
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  };

  return (
    <div className="card-elevated" style={{ padding: "20px 24px", marginBottom: 24 }}>
      {/* Header row */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16, gap: 12, flexWrap: "wrap" }}>
        <div>
          <h2 style={{ margin: "0 0 2px", fontSize: "1rem", fontWeight: 700 }}>Incident Digest</h2>
          <p className="muted small" style={{ margin: 0 }}>Aggregated overview of all runs in the period.</p>
        </div>
        <select
          className="input"
          value={days}
          onChange={handleDaysChange}
          disabled={loading}
          style={{ width: 140, fontSize: 13 }}
        >
          {[7, 14, 30, 90].map((d) => <option key={d} value={d}>Last {d} days</option>)}
        </select>
      </div>

      {err && <p className="error compact" style={{ marginBottom: 12 }}>{err}</p>}

      {loading && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} style={{ flex: "1 1 110px", minWidth: 100, background: "var(--surface-2)", borderRadius: "var(--radius-sm)", padding: "12px 16px", border: "1px solid var(--border)" }}>
                <div className="skeleton" style={{ width: "40%", height: 8, marginBottom: 8 }} />
                <div className="skeleton" style={{ width: "60%", height: 24 }} />
              </div>
            ))}
          </div>
          <div>
            <div className="skeleton" style={{ width: "100px", height: 10, marginBottom: 12 }} />
            <SkeletonRect height={180} />
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
            <div style={{ background: "var(--surface)", borderRadius: "var(--radius-sm)", padding: "14px 16px", border: "1px solid var(--border)" }}>
              <div className="skeleton" style={{ width: "80px", height: 10, marginBottom: 16 }} />
              <SkeletonText lines={4} />
            </div>
            <div style={{ background: "var(--surface)", borderRadius: "var(--radius-sm)", padding: "14px 16px", border: "1px solid var(--border)" }}>
              <div className="skeleton" style={{ width: "80px", height: 10, marginBottom: 16 }} />
              <SkeletonText lines={4} />
            </div>
          </div>
        </div>
      )}

      {digest && !loading && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {/* Stat row */}
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <DigestStatCard label="Total Jobs" value={digest.total_jobs} />
            <DigestStatCard label="Completed" value={digest.completed} valueColor="var(--ok)" />
            <DigestStatCard label="Failed" value={digest.failed} valueColor={digest.failed > 0 ? "var(--danger)" : "var(--muted)"} />
            <DigestStatCard label="Incidents" value={digest.total_incidents} />
            <DigestStatCard label="Avg MTTR" value={digest.mean_mttr_minutes != null ? `${digest.mean_mttr_minutes}m` : "—"} />
          </div>

          {/* Timeseries chart */}
          {daily.length > 0 && (
            <div>
              <p style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)" }}>
                Runs Over Time
              </p>
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={daily} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="dgTotal" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#5eead4" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#5eead4" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="dgFailed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#fb7185" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#fb7185" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(120,162,255,0.08)" />
                  <XAxis
                    dataKey="date"
                    tickFormatter={xTickFormatter}
                    tick={{ fontSize: 10, fill: "var(--muted)" }}
                    axisLine={false}
                    tickLine={false}
                    interval="preserveStartEnd"
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fontSize: 10, fill: "var(--muted)" }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={CHART_TOOLTIP_STYLE}
                    labelFormatter={xTickFormatter}
                    formatter={(val, name) => [val, name.charAt(0).toUpperCase() + name.slice(1)]}
                  />
                  <Area type="monotone" dataKey="total" name="total" stroke="#5eead4" strokeWidth={2} fill="url(#dgTotal)" dot={false} />
                  <Area type="monotone" dataKey="failed" name="failed" stroke="#fb7185" strokeWidth={1.5} fill="url(#dgFailed)" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Severity & Source side-by-side */}
          {(sevEntries.length > 0 || srcEntries.length > 0) && (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              {sevEntries.length > 0 && (
                <div style={{ background: "var(--surface)", borderRadius: "var(--radius-sm)", padding: "14px 16px", border: "1px solid var(--border)" }}>
                  <p style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)" }}>
                    By Severity
                  </p>
                  <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                    {sevEntries.map(([sev, count]) => {
                      const c = SEV_COLORS[sev.toLowerCase()] || SEV_COLORS.unknown;
                      const pct = digest.total_jobs ? Math.round((count / digest.total_jobs) * 100) : 0;
                      return (
                        <div key={sev} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <SevBadge sev={sev} />
                          <div style={{ flex: 1, height: 5, background: "var(--surface-2)", borderRadius: 3, overflow: "hidden" }}>
                            <div style={{ width: `${pct}%`, height: "100%", background: c.text, borderRadius: 3, opacity: 0.7 }} />
                          </div>
                          <span style={{ fontSize: 12, fontWeight: 700, color: c.text, minWidth: 18, textAlign: "right" }}>{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
              {srcEntries.length > 0 && (
                <div style={{ background: "var(--surface)", borderRadius: "var(--radius-sm)", padding: "14px 16px", border: "1px solid var(--border)" }}>
                  <p style={{ margin: "0 0 10px", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.07em", color: "var(--muted)" }}>
                    By Source
                  </p>
                  <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                    {srcEntries.map(([src, count]) => (
                      <div key={src} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ fontSize: 11, fontWeight: 600, color: "var(--text)", minWidth: 64, textTransform: "capitalize" }}>{src}</span>
                        <div style={{ flex: 1, height: 5, background: "var(--surface-2)", borderRadius: 3, overflow: "hidden" }}>
                          <div style={{ width: `${Math.round((count / maxSrc) * 100)}%`, height: "100%", background: "var(--violet)", borderRadius: 3, opacity: 0.7 }} />
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, color: "var(--text)", minWidth: 18, textAlign: "right" }}>{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function runLabel(row) {
  const title = row.title || "Untitled";
  const when = new Date(row.created_at).toLocaleString();
  const st =
    row.status === "completed" ? "Complete" : row.status === "failed" ? "Failed" : row.status === "processing" ? "Running" : "Pending";
  return `${title} — ${when} — ${st}`;
}

function DashboardContent({ tokenProvider = null }) {
  const [jobRows, setJobRows] = useState([]);
  const [loadingJobs, setLoadingJobs] = useState(false);
  const [filterValue, setFilterValue] = useState("");
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");
  const [loadingDetail, setLoadingDetail] = useState(false);

  const loadJobs = useCallback(async () => {
    setLoadingJobs(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const rows = await fetchJobs(20, token);
      setJobRows(rows);
    } catch (err) {
      setError(err.message || "Failed to load runs");
    } finally {
      setLoadingJobs(false);
    }
  }, [tokenProvider]);

  useEffect(() => {
    loadJobs();
  }, [loadJobs]);

  async function onFilterChange(e) {
    const id = e.target.value;
    setFilterValue(id);
    setError("");
    setSelected(null);
    if (!id) return;
    setLoadingDetail(true);
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const data = await fetchJob(id, token);
      setSelected(data);
    } catch (err) {
      setError(err.message || "Failed to load run");
    } finally {
      setLoadingDetail(false);
    }
  }

  return (
    <AppShell activeHref="/dashboard">
      <header className="page-header">
        <div>
          <p className="eyebrow">Operations</p>
          <h1 className="page-title">Dashboard</h1>
          <p className="page-sub muted">Per-run log stats and analysis. Export JSON or PDF below.</p>
          {!clerkEnabled ? <p className="muted small">Clerk disabled (configure keys for SaaS auth).</p> : null}
        </div>
        <div className="page-header-actions" />
      </header>

      <IncidentDigest tokenProvider={tokenProvider} />

      <div className="card-elevated dashboard-filter-bar" style={{ marginBottom: 24, padding: "16px 20px" }}>
        <div className="row gap" style={{ flexWrap: "wrap", alignItems: "center", gap: 12 }}>
          <label className="dashboard-filter-label" style={{ flex: "1 1 280px", minWidth: 0, margin: 0 }}>
            <span className="muted small" style={{ display: "block", marginBottom: 6 }}>
              Run
            </span>
            {loadingJobs ? (
              <SkeletonRect height={38} style={{ width: "100%", borderRadius: 8 }} />
            ) : (
              <select
                className="input"
                value={filterValue}
                onChange={onFilterChange}
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
          <button type="button" className="btn btn-muted" style={{ alignSelf: "flex-end" }} onClick={loadJobs}>
            Refresh list
          </button>
        </div>
        {loadingDetail ? (
          <div style={{ margin: "12px 0 0" }}>
            <SkeletonText lines={1} className="skeleton-rect" style={{ width: "120px", height: 14 }} />
          </div>
        ) : null}
      </div>

      {loadingDetail ? (
        <div className="card-elevated" style={{ padding: "24px" }}>
          <SkeletonTitle />
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24, marginBottom: 24 }}>
            <SkeletonRect height={200} />
            <SkeletonRect height={200} />
          </div>
          <SkeletonText lines={10} />
        </div>
      ) : selected ? (
        <>
          <LogDataCharts result={selected} />
          <AnalysisReport
            result={selected}
            getToken={tokenProvider}
            showRemediation={false}
            showGuardrails={false}
          />
        </>
      ) : !filterValue ? (
        <p className="muted small" style={{ marginBottom: 24 }}>
          Select a <strong>run</strong> above to load charts and the analysis. Start a new analysis on{" "}
          <a className="link-subtle" href="/analyze">
            Analyze
          </a>
          .
        </p>
      ) : null}

      {error ? <p className="error compact">{error}</p> : null}
    </AppShell>
  );
}

function AuthenticatedDashboard() {
  const { getToken } = useAuth();
  return <DashboardContent tokenProvider={getToken} />;
}

export default function Dashboard() {
  if (!clerkEnabled) {
    return <DashboardContent />;
  }

  return (
    <>
      <SignedIn>
        <AuthenticatedDashboard />
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  );
}
