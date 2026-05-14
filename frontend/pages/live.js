import { RedirectToSignIn, SignedIn, SignedOut, useAuth } from "@clerk/nextjs";
import { useEffect, useMemo, useState } from "react";

import AppShell from "../components/AppShell";
import FeatureLockedCard from "../components/FeatureLockedCard";
import { SkeletonRect } from "../components/Skeleton";
import { useEntitlements } from "../context/EntitlementContext";
import {
  createLiveApplication,
  createLiveLogSource,
  createLiveService,
  fetchLiveApplications,
  fetchLiveBoard,
  refreshLiveBoard,
  updateLiveConfig,
} from "../lib/api";
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

function ApplicationCard({ app }) {
  const services = app.services || [];
  const sourceCount = services.reduce((total, svc) => total + (svc.log_sources || []).length, 0);
  const criticalCount = services.filter((svc) => ["high", "critical"].includes(svc.criticality)).length;

  return (
    <article className="live-app-card">
      <div className="live-app-head">
        <div>
          <p className="eyebrow">Monitored application</p>
          <h3 style={{ margin: "0 0 4px" }}>{app.name}</h3>
          <p className="muted small" style={{ margin: 0 }}>
            {app.environment || "production"} • {services.length} services • {sourceCount} log sources
          </p>
        </div>
        <span className={`live-status-pill${app.enabled ? "" : " is-disabled"}`}>{app.enabled ? "enabled" : "paused"}</span>
      </div>
      {app.description ? <p className="muted small" style={{ marginTop: 12 }}>{app.description}</p> : null}
      <div className="live-stat-row live-stat-row-compact">
        <div className="live-stat-box">
          <span className="live-stat-label">Services</span>
          <strong>{services.length}</strong>
        </div>
        <div className="live-stat-box">
          <span className="live-stat-label">Critical</span>
          <strong>{criticalCount}</strong>
        </div>
        <div className="live-stat-box">
          <span className="live-stat-label">Sources</span>
          <strong>{sourceCount}</strong>
        </div>
      </div>
      {services.length ? (
        <div className="live-service-list">
          {services.map((svc) => (
            <div key={svc.id} className="live-service-row">
              <div>
                <strong>{svc.name}</strong>
                <span className="muted small">
                  {svc.service_type || "service"} • {svc.owner || "unassigned"}
                </span>
              </div>
              <div className="live-service-meta">
                <SeverityPill severity={svc.criticality || "medium"} />
                <span className="live-tag">{(svc.log_sources || []).length} sources</span>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="muted small" style={{ marginBottom: 0 }}>
          Add the microservices that make up this application, then attach log sources to each one.
        </p>
      )}
    </article>
  );
}

function EnabledBoard({ tokenProvider = null }) {
  const [board, setBoard] = useState(null);
  const [applications, setApplications] = useState([]);
  const [selectedApplicationId, setSelectedApplicationId] = useState("");
  const [form, setForm] = useState({
    enabled: true,
    logGroupsText: "",
    lookbackMinutes: 5,
    errorThreshold: 5,
  });
  const [appForm, setAppForm] = useState({
    name: "Fintech Switching Platform",
    environment: "production",
    description: "",
  });
  const [serviceForm, setServiceForm] = useState({
    name: "card-switch-service",
    serviceType: "api",
    criticality: "high",
    owner: "",
    dependencyOrder: 0,
  });
  const [sourceForm, setSourceForm] = useState({
    serviceId: "",
    provider: "gcp_cloud_logging",
    sourceRef: "",
    filterQuery: "",
  });
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [savingTopology, setSavingTopology] = useState(false);
  const [error, setError] = useState("");
  const [topologyTab, setTopologyTab] = useState("application");

  async function loadBoard() {
    setLoading(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const [data, appsData] = await Promise.all([
        fetchLiveBoard(token),
        fetchLiveApplications(token),
      ]);
      setBoard(data);
      const nextApps = appsData.applications || [];
      setApplications(nextApps);
      setSelectedApplicationId((current) => current || nextApps[0]?.id || "");
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

  async function reloadApplications(token = null) {
    const nextToken = token || (tokenProvider ? await tokenProvider() : null);
    const data = await fetchLiveApplications(nextToken);
    const nextApps = data.applications || [];
    setApplications(nextApps);
    setSelectedApplicationId((current) => {
      if (current && nextApps.some((app) => app.id === current)) return current;
      return nextApps[0]?.id || "";
    });
    return nextApps;
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

  async function handleCreateApplication(e) {
    e.preventDefault();
    setSavingTopology(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const data = await createLiveApplication({
        name: appForm.name,
        environment: appForm.environment || "production",
        description: appForm.description || null,
        enabled: true,
      }, token);
      const app = data.application;
      const nextApps = await reloadApplications(token);
      setSelectedApplicationId(app?.id || nextApps[0]?.id || "");
      setTopologyTab("service");
    } catch (e) {
      setError(e.message || "Failed to create live application");
    } finally {
      setSavingTopology(false);
    }
  }

  async function handleCreateService(e) {
    e.preventDefault();
    if (!selectedApplicationId) return;
    setSavingTopology(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      const data = await createLiveService(selectedApplicationId, {
        name: serviceForm.name,
        service_type: serviceForm.serviceType || "service",
        criticality: serviceForm.criticality || "medium",
        owner: serviceForm.owner || null,
        dependency_order: Number(serviceForm.dependencyOrder) || 0,
      }, token);
      const service = data.service;
      await reloadApplications(token);
      setSourceForm((prev) => ({ ...prev, serviceId: service?.id || prev.serviceId }));
      setTopologyTab("logsource");
    } catch (e) {
      setError(e.message || "Failed to add service");
    } finally {
      setSavingTopology(false);
    }
  }

  async function handleCreateLogSource(e) {
    e.preventDefault();
    if (!sourceForm.serviceId) return;
    setSavingTopology(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      await createLiveLogSource(sourceForm.serviceId, {
        provider: sourceForm.provider,
        source_type: "log",
        source_ref: sourceForm.sourceRef,
        filter_query: sourceForm.filterQuery || null,
        enabled: true,
      }, token);
      await reloadApplications(token);
      setSourceForm((prev) => ({ ...prev, sourceRef: "", filterQuery: "" }));
    } catch (e) {
      setError(e.message || "Failed to attach log source");
    } finally {
      setSavingTopology(false);
    }
  }

  useEffect(() => {
    loadBoard();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const logGroupsKey = useMemo(
    () => (board?.config?.log_groups || []).join("|"),
    [board?.config?.log_groups]
  );

  const selectedApplication = useMemo(
    () => applications.find((app) => app.id === selectedApplicationId) || applications[0] || null,
    [applications, selectedApplicationId]
  );
  const selectedServices = useMemo(
    () => selectedApplication?.services || [],
    [selectedApplication]
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

  useEffect(() => {
    if (!selectedServices.length) {
      setSourceForm((prev) => ({ ...prev, serviceId: "" }));
      return;
    }
    setSourceForm((prev) => {
      if (prev.serviceId && selectedServices.some((svc) => svc.id === prev.serviceId)) {
        return prev;
      }
      return { ...prev, serviceId: selectedServices[0].id };
    });
  }, [selectedApplicationId, selectedServices]);

  const warnings = board?.warnings || [];
  const incidents = board?.incidents || [];

  const topologyTabMeta = {
    application: {
      title: "Application",
      hint: "Name the system Sentinel should treat as one correlated surface (for example a production payments stack).",
    },
    service: {
      title: "Microservice",
      hint: "Register each deployable unit so signals can be attributed and ordered by dependency.",
    },
    logsource: {
      title: "Log source",
      hint: "Point each service at a log stream or query. Correlation uses this wiring across services.",
    },
  };

  return (
    <>
      <section className="card-elevated live-topology-card">
        <div className="live-board-head live-board-head--tight">
          <div>
            <p className="eyebrow">LiveOps · topology</p>
            <h2 className="live-section-heading">Model your stack, then attach logs</h2>
            <p className="muted small live-hero-lead">
              One application, many services, one log source per stream—so cross-service incidents stay in a single
              narrative. Optional CloudWatch polling lives in the section below.
            </p>
          </div>
          <div className="live-hero-badges">
            <span className="feature-locked-badge">Live enabled</span>
            <span className="live-tag">{applications.length} app{applications.length === 1 ? "" : "s"}</span>
          </div>
        </div>

        <div
          className="live-tablist"
          role="tablist"
          aria-label="Topology setup steps"
        >
          {(["application", "service", "logsource"]).map((id) => (
            <button
              key={id}
              type="button"
              role="tab"
              id={`live-tab-${id}`}
              aria-selected={topologyTab === id}
              aria-controls={`live-tabpanel-${id}`}
              tabIndex={topologyTab === id ? 0 : -1}
              className={`live-tab${topologyTab === id ? " is-active" : ""}`}
              onClick={() => setTopologyTab(id)}
            >
              <span className="live-tab-kicker">{id === "application" ? "1" : id === "service" ? "2" : "3"}</span>
              <span className="live-tab-label">{topologyTabMeta[id].title}</span>
            </button>
          ))}
        </div>
        <p className="live-tab-hint muted small">{topologyTabMeta[topologyTab].hint}</p>

        <div className="live-tab-panels">
          <div
            role="tabpanel"
            id="live-tabpanel-application"
            aria-labelledby="live-tab-application"
            hidden={topologyTab !== "application"}
            className="live-tab-panel"
          >
            <form onSubmit={handleCreateApplication} className="live-config-form live-config-form--tabbed">
              <label>
                <span className="muted small">Application name</span>
                <input
                  className="input"
                  value={appForm.name}
                  onChange={(e) => setAppForm((prev) => ({ ...prev, name: e.target.value }))}
                  placeholder="Fintech Switching Platform"
                />
              </label>
              <div className="live-config-grid">
                <label>
                  <span className="muted small">Environment</span>
                  <input
                    className="input"
                    value={appForm.environment}
                    onChange={(e) => setAppForm((prev) => ({ ...prev, environment: e.target.value }))}
                    placeholder="production"
                  />
                </label>
                <label>
                  <span className="muted small">Description</span>
                  <input
                    className="input"
                    value={appForm.description}
                    onChange={(e) => setAppForm((prev) => ({ ...prev, description: e.target.value }))}
                    placeholder="Payment authorization and settlement"
                  />
                </label>
              </div>
              <div className="live-tab-actions">
                <button type="submit" className="btn" disabled={savingTopology || !appForm.name.trim()}>
                  {savingTopology ? "Saving…" : "Create application"}
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={!applications.length}
                  onClick={() => setTopologyTab("service")}
                >
                  Next: services
                </button>
              </div>
            </form>
          </div>

          <div
            role="tabpanel"
            id="live-tabpanel-service"
            aria-labelledby="live-tab-service"
            hidden={topologyTab !== "service"}
            className="live-tab-panel"
          >
            <form onSubmit={handleCreateService} className="live-config-form live-config-form--tabbed">
              <label>
                <span className="muted small">Application</span>
                <select
                  className="input"
                  value={selectedApplicationId}
                  onChange={(e) => setSelectedApplicationId(e.target.value)}
                >
                  {applications.length ? applications.map((app) => (
                    <option key={app.id} value={app.id}>{app.name} ({app.environment})</option>
                  )) : <option value="">Create an application in the previous tab first</option>}
                </select>
              </label>
              <div className="live-config-grid">
                <label>
                  <span className="muted small">Service name</span>
                  <input
                    className="input"
                    value={serviceForm.name}
                    onChange={(e) => setServiceForm((prev) => ({ ...prev, name: e.target.value }))}
                    placeholder="ledger-service"
                  />
                </label>
                <label>
                  <span className="muted small">Criticality</span>
                  <select
                    className="input"
                    value={serviceForm.criticality}
                    onChange={(e) => setServiceForm((prev) => ({ ...prev, criticality: e.target.value }))}
                  >
                    <option value="critical">critical</option>
                    <option value="high">high</option>
                    <option value="medium">medium</option>
                    <option value="low">low</option>
                  </select>
                </label>
                <label>
                  <span className="muted small">Type</span>
                  <input
                    className="input"
                    value={serviceForm.serviceType}
                    onChange={(e) => setServiceForm((prev) => ({ ...prev, serviceType: e.target.value }))}
                    placeholder="api, worker, queue-consumer"
                  />
                </label>
                <label>
                  <span className="muted small">Owner</span>
                  <input
                    className="input"
                    value={serviceForm.owner}
                    onChange={(e) => setServiceForm((prev) => ({ ...prev, owner: e.target.value }))}
                    placeholder="payments-platform"
                  />
                </label>
              </div>
              <div className="live-tab-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setTopologyTab("application")}>
                  Back
                </button>
                <button type="submit" className="btn" disabled={savingTopology || !selectedApplicationId || !serviceForm.name.trim()}>
                  {savingTopology ? "Saving…" : "Add service"}
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={!selectedServices.length}
                  onClick={() => setTopologyTab("logsource")}
                >
                  Next: log sources
                </button>
              </div>
            </form>
          </div>

          <div
            role="tabpanel"
            id="live-tabpanel-logsource"
            aria-labelledby="live-tab-logsource"
            hidden={topologyTab !== "logsource"}
            className="live-tab-panel"
          >
            <form onSubmit={handleCreateLogSource} className="live-config-form live-config-form--tabbed">
              <label>
                <span className="muted small">Service</span>
                <select
                  className="input"
                  value={sourceForm.serviceId}
                  onChange={(e) => setSourceForm((prev) => ({ ...prev, serviceId: e.target.value }))}
                >
                  {selectedServices.length ? selectedServices.map((svc) => (
                    <option key={svc.id} value={svc.id}>{svc.name}</option>
                  )) : <option value="">Add a service in the previous tab first</option>}
                </select>
              </label>
              <div className="live-config-grid">
                <label>
                  <span className="muted small">Provider</span>
                  <select
                    className="input"
                    value={sourceForm.provider}
                    onChange={(e) => setSourceForm((prev) => ({ ...prev, provider: e.target.value }))}
                  >
                    <option value="gcp_cloud_logging">GCP Cloud Logging</option>
                    <option value="aws_cloudwatch">AWS CloudWatch</option>
                    <option value="webhook">Generic webhook</option>
                    <option value="opentelemetry">OpenTelemetry</option>
                  </select>
                </label>
                <label>
                  <span className="muted small">Source reference</span>
                  <input
                    className="input"
                    value={sourceForm.sourceRef}
                    onChange={(e) => setSourceForm((prev) => ({ ...prev, sourceRef: e.target.value }))}
                    placeholder='resource.labels.service_name="card-switch-service"'
                  />
                </label>
              </div>
              <label>
                <span className="muted small">Optional filter query</span>
                <textarea
                  className="input live-config-textarea live-config-textarea--compact"
                  value={sourceForm.filterQuery}
                  onChange={(e) => setSourceForm((prev) => ({ ...prev, filterQuery: e.target.value }))}
                  placeholder='severity>=ERROR OR textPayload:"timeout"'
                />
              </label>
              <div className="live-tab-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setTopologyTab("service")}>
                  Back
                </button>
                <button type="submit" className="btn" disabled={savingTopology || !sourceForm.serviceId || !sourceForm.sourceRef.trim()}>
                  {savingTopology ? "Saving…" : "Attach log source"}
                </button>
              </div>
            </form>
          </div>
        </div>

        <div className="live-topology-divider" aria-hidden="true" />
        <p className="live-section-title live-section-title--inline">Monitored applications</p>
        <div className="live-app-grid">
          {applications.length ? (
            applications.map((app) => <ApplicationCard key={app.id} app={app} />)
          ) : (
            <div className="live-app-empty">
              <p style={{ margin: "0 0 6px", fontWeight: 600 }}>No monitored applications yet</p>
              <p className="muted small" style={{ margin: 0 }}>
                Start by creating the business application, then add the 10-15 services that make it work.
              </p>
            </div>
          )}
        </div>
      </section>

      <details className="live-legacy-details">
        <summary className="live-legacy-summary">
          <span className="live-legacy-summary-title">Legacy CloudWatch polling</span>
          <span className="muted small live-legacy-summary-meta">Optional · classic log-group watcher</span>
        </summary>
        <div className="live-legacy-body">
        <form onSubmit={handleSave} className="live-config-form live-config-form--legacy">
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
        </div>
      </details>

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
                Open <strong>Legacy CloudWatch polling</strong> below, add log groups, save, then refresh. Sentinel opens
                a live incident when burst and pattern thresholds are crossed.
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
            Multi-service topology, log correlation, and optional CloudWatch polling in one place.
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
