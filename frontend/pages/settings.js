import { RedirectToSignIn, SignedIn, SignedOut, useAuth } from "@clerk/nextjs";
import { useCallback, useEffect, useState } from "react";

import AppShell from "../components/AppShell";
import { deleteIntegration, fetchIntegrations, saveIntegration } from "../lib/api";
import { SkeletonRect, SkeletonText, SkeletonTitle } from "../components/Skeleton";
import { isClerkEnabled } from "../lib/clerk";

const clerkEnabled = isClerkEnabled();

const INTEGRATION_TYPES = [
  { value: "slack", label: "Slack", fields: [{ key: "webhook_url", label: "Webhook URL", placeholder: "https://hooks.slack.com/services/…" }] },
  {
    value: "jira",
    label: "Jira",
    fields: [
      { key: "base_url", label: "Base URL", placeholder: "https://yourorg.atlassian.net" },
      { key: "project_key", label: "Project Key", placeholder: "OPS" },
      { key: "email", label: "Email", placeholder: "you@company.com" },
      { key: "api_token", label: "API Token", placeholder: "…", secret: true },
    ],
  },
  {
    value: "pagerduty",
    label: "PagerDuty",
    fields: [{ key: "routing_key", label: "Routing Key (Events v2)", placeholder: "…", secret: true }],
  },
  { value: "generic_webhook", label: "Generic Webhook", fields: [{ key: "webhook_url", label: "Webhook URL", placeholder: "https://…" }] },
];

function IntegrationForm({ onSave, loading }) {
  const [type, setType] = useState("slack");
  const [config, setConfig] = useState({});
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");

  const typeDef = INTEGRATION_TYPES.find((t) => t.value === type) || INTEGRATION_TYPES[0];

  function setField(key, value) {
    setConfig((prev) => ({ ...prev, [key]: value }));
  }

  async function handleSave() {
    setSaving(true);
    setErr("");
    try {
      await onSave({ type, config, enabled: true });
      setConfig({});
    } catch (e) {
      setErr(e.message || "Failed to save");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <div className="card-elevated" style={{ padding: "20px 24px", marginBottom: 24 }}>
        <SkeletonTitle />
        <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 12 }}>
          <SkeletonRect height={38} />
          <SkeletonRect height={38} />
          <SkeletonRect height={42} style={{ width: 140 }} />
        </div>
      </div>
    );
  }

  return (
    <div className="card-elevated" style={{ padding: "20px 24px", marginBottom: 24 }}>
      <h3 style={{ margin: "0 0 16px" }}>Add Integration</h3>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 12 }}>
        <select
          className="input"
          value={type}
          onChange={(e) => { setType(e.target.value); setConfig({}); }}
          style={{ flex: "0 0 180px" }}
        >
          {INTEGRATION_TYPES.map((t) => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 16 }}>
        {typeDef.fields.map((f) => (
          <label key={f.key} style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            <span className="muted small">{f.label}</span>
            <input
              className="input"
              type={f.secret ? "password" : "text"}
              placeholder={f.placeholder}
              value={config[f.key] || ""}
              onChange={(e) => setField(f.key, e.target.value)}
            />
          </label>
        ))}
      </div>
      {err ? <p className="error compact" style={{ marginBottom: 8 }}>{err}</p> : null}
      <button type="button" className="btn" onClick={handleSave} disabled={saving}>
        {saving ? "Saving…" : "Save Integration"}
      </button>
    </div>
  );
}

function SettingsContent({ tokenProvider = null }) {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      if (tokenProvider && !token) {
        setError("Could not get a session token. Try refreshing the page, or sign out and sign in again.");
        return;
      }
      const data = await fetchIntegrations(token);
      setIntegrations(Array.isArray(data) ? data : []);
    } catch (err) {
      setError(err.message || "Failed to load integrations");
    } finally {
      setLoading(false);
    }
  }, [tokenProvider]);

  useEffect(() => { load(); }, [load]);

  async function handleSave(payload) {
    setError("");
    const token = tokenProvider ? await tokenProvider() : null;
    if (tokenProvider && !token) {
      setError("Could not get a session token. Try refreshing the page.");
      return;
    }
    await saveIntegration(payload, token);
    await load();
  }

  async function handleDelete(id) {
    setError("");
    try {
      const token = tokenProvider ? await tokenProvider() : null;
      if (tokenProvider && !token) {
        setError("Could not get a session token. Try refreshing the page.");
        return;
      }
      await deleteIntegration(id, token);
      setIntegrations((prev) => prev.filter((i) => (i.id || i.integration_id) !== id));
    } catch (err) {
      setError(err.message || "Failed to delete");
    }
  }

  return (
    <AppShell activeHref="/settings">
      <header className="page-header">
        <div>
          <p className="eyebrow">Configuration</p>
          <h1 className="page-title">Settings</h1>
          <p className="page-sub muted">Manage integrations and generate digest reports.</p>
        </div>
      </header>

      {error ? <p className="error compact" style={{ marginBottom: 16 }}>{error}</p> : null}

      <h2 style={{ marginBottom: 16 }}>Integrations</h2>

      <IntegrationForm onSave={handleSave} loading={loading} />

      {loading ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {[1, 2, 3].map((i) => (
            <SkeletonRect key={i} height={60} style={{ borderRadius: "var(--radius, 12px)" }} />
          ))}
        </div>
      ) : integrations.length === 0 ? (
        <p className="muted small">No integrations configured yet.</p>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {integrations.map((int) => (
            <div
              key={int.id || int.integration_id}
              className="card-elevated"
              style={{
                padding: "14px 18px",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                gap: 12,
              }}
            >
              <div>
                <span style={{ fontWeight: 600, textTransform: "capitalize" }}>{int.type}</span>
                <span
                  style={{
                    marginLeft: 10,
                    fontSize: 11,
                    fontWeight: 600,
                    padding: "2px 7px",
                    borderRadius: 5,
                    background: int.enabled ? "var(--accent-dim)" : "var(--surface-2)",
                    color: int.enabled ? "var(--accent)" : "var(--muted)",
                  }}
                >
                  {int.enabled ? "Active" : "Disabled"}
                </span>
                <span className="muted small" style={{ marginLeft: 10 }}>
                  Added {new Date(int.created_at).toLocaleDateString()}
                </span>
              </div>
              <button
                type="button"
                className="btn btn-muted"
                style={{ color: "var(--danger)", borderColor: "var(--danger)" }}
                onClick={() => handleDelete(int.id || int.integration_id)}
              >
                Remove
              </button>
            </div>
          ))}
        </div>
      )}
    </AppShell>
  );
}

function AuthenticatedSettings() {
  const { getToken, isLoaded, isSignedIn } = useAuth();
  const [sessionReady, setSessionReady] = useState(false);
  const [prepError, setPrepError] = useState("");

  // `isLoaded` alone is not always enough: `getToken()` can briefly return null right after.
  useEffect(() => {
    if (!isLoaded || !isSignedIn) {
      setSessionReady(false);
      setPrepError("");
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const t = await getToken();
        if (cancelled) return;
        if (t) {
          setSessionReady(true);
          setPrepError("");
        } else {
          setSessionReady(false);
          setPrepError("Clerk did not return an API token. Check Clerk Dashboard → JWT templates and try signing out and back in.");
        }
      } catch (e) {
        if (!cancelled) {
          setSessionReady(false);
          setPrepError(e?.message || "Could not load a session token from Clerk.");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isLoaded, isSignedIn, getToken]);

  if (!isLoaded) {
    return (
      <AppShell activeHref="/settings">
        <header className="page-header">
          <div>
            <p className="eyebrow">Configuration</p>
            <h1 className="page-title">Settings</h1>
            <p className="page-sub muted">Loading your session…</p>
          </div>
        </header>
      </AppShell>
    );
  }

  if (!isSignedIn) {
    return <RedirectToSignIn />;
  }

  if (!sessionReady) {
    return (
      <AppShell activeHref="/settings">
        <header className="page-header">
          <div>
            <p className="eyebrow">Configuration</p>
            <h1 className="page-title">Settings</h1>
            <p className="page-sub muted">Preparing your secure session…</p>
          </div>
        </header>
        {prepError ? <p className="error compact" style={{ marginTop: 16 }}>{prepError}</p> : null}
      </AppShell>
    );
  }

  return <SettingsContent tokenProvider={getToken} />;
}

export default function Settings() {
  if (!clerkEnabled) {
    return <SettingsContent />;
  }

  return (
    <>
      <SignedIn>
        <AuthenticatedSettings />
      </SignedIn>
      <SignedOut>
        <RedirectToSignIn />
      </SignedOut>
    </>
  );
}
