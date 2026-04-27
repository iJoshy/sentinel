import { RedirectToSignIn, SignedIn, SignedOut, useAuth } from "@clerk/nextjs";
import { useEffect, useMemo, useState } from "react";

import AppShell from "../components/AppShell";
import FeatureLockedCard from "../components/FeatureLockedCard";
import { SkeletonRect } from "../components/Skeleton";
import { useEntitlements } from "../context/EntitlementContext";
import { fetchLiveBoard, refreshLiveBoard, updateLiveConfig } from "../lib/api";
import { isClerkEnabled } from "../lib/clerk";

const clerkEnabled = isClerkEnabled();

function LockedPreview() {
  return (
    <>
      <FeatureLockedCard
        title="Live Incident Board"
        description="Monitor CloudWatch logs in real time and auto-open live incidents when threshold and pattern rules are crossed."
      />

      <section className="live-preview-grid">
        <div className="card-elevated live-preview-card">
          <p className="eyebrow">What You Unlock</p>
          <h3 style={{ marginTop: 0 }}>Continuous incident watch</h3>
          <p className="muted small" style={{ marginBottom: 0 }}>
            Sentinel watches selected CloudWatch log groups, detects spikes in errors, exceptions, timeouts, and auth
            failures, then opens a live incident with evidence-backed RCA and next actions.
          </p>
        </div>
        <div className="card-elevated live-preview-card">
          <p className="eyebrow">Board Preview</p>
          <h3 style={{ marginTop: 0 }}>Live incident story</h3>
          <ul className="live-preview-list">
            <li>Active incident status and severity</li>
            <li>Top evidence snippets from the log stream</li>
            <li>Evolving likely root cause and confidence</li>
            <li>Raw CloudWatch tail as supporting context</li>
          </ul>
        </div>
      </section>
    </>
  );
}

function formatWhen(value) {
  if (!value) return "—";
  try {
    return new Date(value).toLocaleString();
  } catch {
    return value;
  }
}

function SeverityPill({ severity }) {
  return <span className={`live-severity-pill sev-${severity || "medium"}`}>{severity || "medium"}</span>;
}

function IncidentCard({ item }) {
  const analysis = item.analysis || {};
  const summary = analysis.summary || {};
  const root = analysis.root_cause || {};
  const remediation = analysis.remediation || {};

  return (
    <article className="card-elevated live-incident-card">
      <div className="live-incident-head">
        <div>
          <p className="eyebrow">Live incident</p>
          <h3 style={{ margin: "0 0 6px" }}>{item.title}</h3>
          <p className="muted small" style={{ margin: 0 }}>
            Last seen {formatWhen(item.last_seen_at)} • First seen {formatWhen(item.first_seen_at)}
          </p>
        </div>
        <div className="live-incident-head-meta">
          <SeverityPill severity={item.severity} />
          <span className="live-status-pill">{item.status || "open"}</span>
        </div>
      </div>

      <div className="live-stat-row">
        <div className="live-stat-box">
          <span className="live-stat-label">Events</span>
          <strong>{item.event_count ?? 0}</strong>
        </div>
        <div className="live-stat-box">
          <span className="live-stat-label">Job</span>
          <strong>{item.latest_job_id ? item.latest_job_id.slice(0, 8) : "—"}</strong>
        </div>
        <div className="live-stat-box">
          <span className="live-stat-label">Analysis</span>
          <strong>{formatWhen(item.last_analysis_at)}</strong>
        </div>
      </div>

      <div className="live-tag-list">
        {item.source_log_groups?.map((group) => (
          <span key={group} className="live-tag">
            {group}
          </span>
        ))}
      </div>

      <div className="live-incident-grid">
        <section>
          <p className="live-section-title">Evidence</p>
          <ul className="live-evidence-list">
            {(item.evidence || []).map((ev, idx) => (
              <li key={`${ev.timestamp}-${idx}`}>
                <span className="live-evidence-meta">
                  {ev.log_group} • {formatWhen(ev.timestamp)}
                </span>
                <code>{ev.message}</code>
              </li>
            ))}
            {!item.evidence?.length ? <li className="muted small">No evidence captured yet.</li> : null}
          </ul>
        </section>

        <section>
          <p className="live-section-title">Current analysis</p>
          {summary.summary ? (
            <div className="live-analysis-block">
              <p style={{ marginTop: 0 }}>{summary.summary}</p>
              <p className="muted small">
                <strong>Severity reason:</strong> {summary.severity_reason || "—"}
              </p>
              <p className="muted small">
                <strong>Root cause:</strong> {root.likely_root_cause || "Pending"}
              </p>
              <p className="muted small">
                <strong>Confidence:</strong> {root.confidence || "—"}
              </p>
              {remediation.recommended_actions?.length ? (
                <ul className="live-action-list">
                  {remediation.recommended_actions.slice(0, 3).map((action) => (
                    <li key={action}>{action}</li>
                  ))}
                </ul>
              ) : (
                <p className="muted small" style={{ marginBottom: 0 }}>
                  Analysis is still pending or no remediation has been generated yet.
                </p>
              )}
            </div>
          ) : (
            <p className="muted small" style={{ marginTop: 0 }}>
              Analysis has not completed yet for this live incident snapshot.
            </p>
          )}
        </section>
      </div>
    </article>
  );
}

function EnabledBoard({ tokenProvider = null }) {
  const [board, setBoard] = useState(null);
  const [form, setForm] = useState({
    enabled: true,
    logGroupsText: "",
    lookbackMinutes: 5,
    errorThreshold: 5,
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  async function loadBoard() {
    setLoading(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const data = await fetchLiveBoard(token);
      setBoard(data);
      const cfg = data.config || {};
      setForm({
        enabled: cfg.enabled !== false,
        logGroupsText: (cfg.log_groups || []).join("\n"),
        lookbackMinutes: cfg.lookback_minutes || 5,
        errorThreshold: cfg.error_threshold || 5,
      });
    } catch (e) {
      setError(e.message || "Failed to load Live Incident Board");
    } finally {
      setLoading(false);
    }
  }

  async function handleSave(e) {
    e.preventDefault();
    setSaving(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const payload = {
        enabled: form.enabled,
        log_groups: form.logGroupsText.split("\n").map((item) => item.trim()).filter(Boolean),
        lookback_minutes: Number(form.lookbackMinutes) || 5,
        error_threshold: Number(form.errorThreshold) || 5,
      };
      const data = await updateLiveConfig(payload, token);
      const cfg = data.config || {};
      setBoard((prev) => ({ ...(prev || {}), config: cfg }));
      setForm({
        enabled: cfg.enabled !== false,
        logGroupsText: (cfg.log_groups || []).join("\n"),
        lookbackMinutes: cfg.lookback_minutes || 5,
        errorThreshold: cfg.error_threshold || 5,
      });
    } catch (e) {
      setError(e.message || "Failed to save monitor config");
    } finally {
      setSaving(false);
    }
  }

  async function handleRefresh() {
    setRefreshing(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const data = await refreshLiveBoard(token);
      setBoard(data);
      const cfg = data.config || {};
      setForm({
        enabled: cfg.enabled !== false,
        logGroupsText: (cfg.log_groups || []).join("\n"),
        lookbackMinutes: cfg.lookback_minutes || 5,
        errorThreshold: cfg.error_threshold || 5,
      });
    } catch (e) {
      setError(e.message || "Failed to refresh live incidents");
    } finally {
      setRefreshing(false);
    }
  }

  useEffect(() => {
    loadBoard();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const logGroupsKey = useMemo(
    () => (board?.config?.log_groups || []).join("|"),
    [board?.config?.log_groups]
  );

  useEffect(() => {
    if (!board?.config?.enabled || !(board?.config?.log_groups || []).length) {
      return undefined;
    }
    const timer = setInterval(() => {
      handleRefresh();
    }, 30000);
    return () => clearInterval(timer);
  }, [board?.config?.enabled, logGroupsKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const warnings = board?.warnings || [];
  const incidents = board?.incidents || [];

  return (
    <>
      <section className="card-elevated live-board-shell">
        <div className="live-board-head">
          <div>
            <p className="eyebrow">LiveOps</p>
            <h2 style={{ margin: "0 0 6px" }}>CloudWatch Live Incident Board</h2>
            <p className="page-sub muted" style={{ margin: 0 }}>
              Configure the log groups you want Sentinel to watch. The board will poll CloudWatch, detect bursts, and
              open or update live incidents for your team.
            </p>
          </div>
          <span className="feature-locked-badge">Enabled</span>
        </div>
      </section>

      <section className="card-elevated live-config-card">
        <form onSubmit={handleSave} className="live-config-form">
          <label className="live-config-toggle">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm((prev) => ({ ...prev, enabled: e.target.checked }))}
            />
            <span>Enable CloudWatch polling for this account</span>
          </label>

          <label>
            <span className="muted small">CloudWatch log groups</span>
            <textarea
              className="input live-config-textarea"
              value={form.logGroupsText}
              onChange={(e) => setForm((prev) => ({ ...prev, logGroupsText: e.target.value }))}
              placeholder={"/aws/lambda/payments-api\n/aws/ecs/platform-gateway"}
            />
          </label>

          <div className="live-config-grid">
            <label>
              <span className="muted small">Initial lookback (minutes)</span>
              <input
                className="input"
                type="number"
                min="1"
                max="60"
                value={form.lookbackMinutes}
                onChange={(e) => setForm((prev) => ({ ...prev, lookbackMinutes: e.target.value }))}
              />
            </label>
            <label>
              <span className="muted small">Burst threshold</span>
              <input
                className="input"
                type="number"
                min="1"
                max="100"
                value={form.errorThreshold}
                onChange={(e) => setForm((prev) => ({ ...prev, errorThreshold: e.target.value }))}
              />
            </label>
          </div>

          <div className="feature-locked-actions">
            <button type="submit" className="btn" disabled={saving}>
              {saving ? "Saving…" : "Save config"}
            </button>
            <button type="button" className="btn btn-secondary" onClick={handleRefresh} disabled={refreshing || loading}>
              {refreshing ? "Refreshing…" : "Refresh CloudWatch now"}
            </button>
            <p className="muted small" style={{ margin: 0 }}>
              Last polled: {formatWhen(board?.config?.last_polled_at)}
            </p>
          </div>
        </form>
      </section>

      {error ? <p className="error compact">{error}</p> : null}
      {warnings.length ? (
        <section className="card-elevated live-warning-card">
          <p className="eyebrow">Warnings</p>
          <ul className="live-preview-list" style={{ marginBottom: 0 }}>
            {warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        </section>
      ) : null}

      {loading ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <SkeletonRect height={200} style={{ borderRadius: "var(--radius, 12px)" }} />
          <SkeletonRect height={200} style={{ borderRadius: "var(--radius, 12px)" }} />
        </div>
      ) : (
        <section className="live-incident-stack">
          {incidents.length ? (
            incidents.map((item) => <IncidentCard key={item.id} item={item} />)
          ) : (
            <div className="card-elevated live-loading-card">
              <p style={{ margin: "0 0 6px", fontWeight: 600 }}>No live incidents yet</p>
              <p className="muted small" style={{ margin: 0 }}>
                Save at least one CloudWatch log group above, then refresh. Sentinel will create a live incident when
                the configured burst and pattern thresholds are crossed.
              </p>
            </div>
          )}
        </section>
      )}
    </>
  );
}

function LiveContent({ tokenProvider = null }) {
  const { hasFeature, loading } = useEntitlements();
  const enabled = hasFeature("live_incident_board");

  return (
    <AppShell activeHref="/live">
      <header className="page-header">
        <div>
          <p className="eyebrow">Premium Operations</p>
          <h1 className="page-title">Live Incident Board</h1>
          <p className="page-sub muted">
            CloudWatch-powered live incident detection for SRE and platform teams.
          </p>
        </div>
      </header>

      {loading ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
          <SkeletonRect height={100} style={{ borderRadius: "var(--radius, 12px)" }} />
          <SkeletonRect height={300} style={{ borderRadius: "var(--radius, 12px)" }} />
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <SkeletonRect height={150} />
            <SkeletonRect height={150} />
          </div>
        </div>
      ) : enabled ? (
        <EnabledBoard tokenProvider={tokenProvider} />
      ) : (
        <LockedPreview />
      )}
    </AppShell>
  );
}

function AuthenticatedLive() {
  const { getToken } = useAuth();
  return <LiveContent tokenProvider={getToken} />;
}

export default function LivePage() {
  if (!clerkEnabled) {
    return <LiveContent />;
  }

  return (
    <>
      <SignedIn>
        <AuthenticatedLive />
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  );
}
