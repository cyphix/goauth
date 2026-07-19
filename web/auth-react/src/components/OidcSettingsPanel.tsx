import { type FormEvent, useState } from "react";

import {
  useAuthSettings,
  useCreateOidcProvider,
  useDeleteOidcProvider,
  useOidcProviders,
  useUpdateAuthSettings,
  useUpdateOidcProvider,
} from "../hooks.ts";
import type { OidcMode, OidcProviderAdmin } from "../types.ts";

export interface OidcSettingsPanelProps {
  className?: string;
}

const MODE_DESCRIPTIONS: Record<OidcMode, string> = {
  disabled: "Local login only (username/password and passkeys).",
  optional:
    "Local login stays available; OIDC providers are listed as an extra button on the login page.",
  required:
    "OIDC is the default and required. The login page is bypassed and users go straight to the provider; password and passkey login are turned off.",
};

/** Admin panel: OIDC mode plus provider CRUD. */
export function OidcSettingsPanel({ className }: OidcSettingsPanelProps) {
  const { data: settings } = useAuthSettings();
  const { data: providers, isLoading } = useOidcProviders();
  const updateSettings = useUpdateAuthSettings();
  const deleteProvider = useDeleteOidcProvider();
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<OidcProviderAdmin | null>(null);
  const [showForm, setShowForm] = useState(false);

  const handleModeChange = (mode: OidcMode) => {
    setError(null);
    updateSettings.mutate(
      { oidcMode: mode },
      { onError: (err) => setError(err.message) }
    );
  };

  return (
    <section className={cx("goauth-panel", className)}>
      <h3 className="goauth-panel-title">OIDC / Single sign-on</h3>

      {error ? <div className="goauth-error">{error}</div> : null}

      <fieldset className="goauth-mode-picker">
        <legend>Mode</legend>
        {(Object.keys(MODE_DESCRIPTIONS) as OidcMode[]).map((mode) => (
          <label className="goauth-radio" key={mode}>
            <input
              checked={settings?.oidcMode === mode}
              name="goauth-oidc-mode"
              onChange={() => handleModeChange(mode)}
              type="radio"
              value={mode}
            />
            <span>
              <strong>{modeLabel(mode)}</strong>
              <span className="goauth-muted"> — {MODE_DESCRIPTIONS[mode]}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <h4 className="goauth-panel-subtitle">Providers</h4>
      {isLoading ? (
        <p className="goauth-muted">Loading…</p>
      ) : providers && providers.length > 0 ? (
        <ul className="goauth-list">
          {providers.map((provider) => (
            <li className="goauth-list-item" key={provider.id}>
              <div>
                <strong>{provider.name}</strong>
                {provider.enabled ? null : (
                  <span className="goauth-badge">disabled</span>
                )}
                <div className="goauth-muted">{provider.issuerUrl}</div>
              </div>
              <div className="goauth-actions">
                <button
                  className="goauth-button"
                  onClick={() => {
                    setEditing(provider);
                    setShowForm(true);
                  }}
                  type="button"
                >
                  Edit
                </button>
                <button
                  className="goauth-button goauth-button-danger"
                  onClick={() =>
                    deleteProvider.mutate(provider.id, {
                      onError: (err) => setError(err.message),
                    })
                  }
                  type="button"
                >
                  Delete
                </button>
              </div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="goauth-muted">No providers configured.</p>
      )}

      {showForm ? (
        <OidcProviderForm
          onClose={() => {
            setEditing(null);
            setShowForm(false);
          }}
          provider={editing}
        />
      ) : (
        <button
          className="goauth-button goauth-button-primary"
          onClick={() => setShowForm(true)}
          type="button"
        >
          Add provider
        </button>
      )}
    </section>
  );
}

interface OidcProviderFormProps {
  provider: OidcProviderAdmin | null;
  onClose: () => void;
}

function OidcProviderForm({ provider, onClose }: OidcProviderFormProps) {
  const createProvider = useCreateOidcProvider();
  const updateProvider = useUpdateOidcProvider();

  const [name, setName] = useState(provider?.name ?? "");
  const [issuerUrl, setIssuerUrl] = useState(provider?.issuerUrl ?? "");
  const [clientId, setClientId] = useState(provider?.clientId ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [scopes, setScopes] = useState(provider?.scopes ?? "");
  const [autoProvision, setAutoProvision] = useState(
    provider?.autoProvision ?? true
  );
  const [enabled, setEnabled] = useState(provider?.enabled ?? true);
  const [error, setError] = useState<string | null>(null);

  const isEdit = provider !== null;
  const pending = createProvider.isPending || updateProvider.isPending;

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const input = {
      name,
      issuerUrl,
      clientId,
      // Empty secret on edit keeps the stored one.
      clientSecret: clientSecret || undefined,
      scopes,
      autoProvision,
      enabled,
    };
    const callbacks = {
      onSuccess: onClose,
      onError: (err: Error) => setError(err.message),
    };
    if (isEdit) {
      updateProvider.mutate({ id: provider.id, input }, callbacks);
    } else {
      createProvider.mutate(input, callbacks);
    }
  };

  return (
    <form className="goauth-provider-form" onSubmit={handleSubmit}>
      <h5>{isEdit ? `Edit ${provider.name}` : "New provider"}</h5>
      {error ? <div className="goauth-error">{error}</div> : null}
      <label className="goauth-field">
        <span>Display name</span>
        <input
          onChange={(e) => setName(e.target.value)}
          placeholder="Authentik"
          required
          value={name}
        />
      </label>
      <label className="goauth-field">
        <span>Issuer URL</span>
        <input
          onChange={(e) => setIssuerUrl(e.target.value)}
          placeholder="https://authentik.example.com/application/o/myapp/"
          required
          type="url"
          value={issuerUrl}
        />
      </label>
      <label className="goauth-field">
        <span>Client ID</span>
        <input
          onChange={(e) => setClientId(e.target.value)}
          required
          value={clientId}
        />
      </label>
      <label className="goauth-field">
        <span>Client secret{isEdit ? " (leave blank to keep current)" : ""}</span>
        <input
          onChange={(e) => setClientSecret(e.target.value)}
          required={!isEdit}
          type="password"
          value={clientSecret}
        />
      </label>
      <label className="goauth-field">
        <span>Extra scopes (space separated)</span>
        <input
          onChange={(e) => setScopes(e.target.value)}
          placeholder="email"
          value={scopes}
        />
      </label>
      <label className="goauth-checkbox">
        <input
          checked={autoProvision}
          onChange={(e) => setAutoProvision(e.target.checked)}
          type="checkbox"
        />
        <span>Auto-provision unknown users on first login</span>
      </label>
      <label className="goauth-checkbox">
        <input
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
          type="checkbox"
        />
        <span>Enabled</span>
      </label>
      <div className="goauth-actions">
        <button
          className="goauth-button goauth-button-primary"
          disabled={pending}
          type="submit"
        >
          {isEdit ? "Save" : "Create"}
        </button>
        <button className="goauth-button" onClick={onClose} type="button">
          Cancel
        </button>
      </div>
    </form>
  );
}

function modeLabel(mode: OidcMode): string {
  switch (mode) {
    case "disabled":
      return "Local only";
    case "optional":
      return "Listed option";
    case "required":
      return "Required (exclusive)";
    default:
      return mode;
  }
}

function cx(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
