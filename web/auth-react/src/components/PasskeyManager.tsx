import { type FormEvent, useState } from "react";

import { useDeletePasskey, usePasskeyRegister, usePasskeys } from "../hooks.ts";

export interface PasskeyManagerProps {
  className?: string;
}

/** Lists the current user's passkeys with add/remove controls. */
export function PasskeyManager({ className }: PasskeyManagerProps) {
  const { data: passkeys, isLoading } = usePasskeys();
  const registerPasskey = usePasskeyRegister();
  const deletePasskey = useDeletePasskey();
  const [name, setName] = useState("");

  const handleRegister = (event: FormEvent) => {
    event.preventDefault();
    registerPasskey.mutate(name || "Passkey", {
      onSuccess: () => setName(""),
    });
  };

  return (
    <section className={cx("goauth-panel", className)}>
      <h3 className="goauth-panel-title">Passkeys</h3>

      {isLoading ? (
        <p className="goauth-muted">Loading…</p>
      ) : passkeys && passkeys.length > 0 ? (
        <ul className="goauth-list">
          {passkeys.map((passkey) => (
            <li className="goauth-list-item" key={passkey.id}>
              <div>
                <strong>{passkey.name}</strong>
                <span className="goauth-muted">
                  {" "}
                  · added {formatDate(passkey.createdAt)}
                  {passkey.lastUsedAt
                    ? ` · last used ${formatDate(passkey.lastUsedAt)}`
                    : ""}
                </span>
              </div>
              <button
                className="goauth-button goauth-button-danger"
                disabled={deletePasskey.isPending}
                onClick={() => deletePasskey.mutate(passkey.id)}
                type="button"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="goauth-muted">No passkeys registered.</p>
      )}

      <form className="goauth-inline-form" onSubmit={handleRegister}>
        <input
          onChange={(e) => setName(e.target.value)}
          placeholder="Passkey name (e.g. laptop)"
          value={name}
        />
        <button
          className="goauth-button goauth-button-primary"
          disabled={registerPasskey.isPending}
          type="submit"
        >
          {registerPasskey.isPending ? "Waiting…" : "Add passkey"}
        </button>
      </form>

      {registerPasskey.error ? (
        <div className="goauth-error">{registerPasskey.error.message}</div>
      ) : null}
      {deletePasskey.error ? (
        <div className="goauth-error">{deletePasskey.error.message}</div>
      ) : null}
    </section>
  );
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString();
}

function cx(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
