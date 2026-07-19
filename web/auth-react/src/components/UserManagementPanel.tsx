import { type FormEvent, useState } from "react";

import {
  useAdminCreateUser,
  useAdminDeleteUser,
  useAdminUpdateUser,
  useAdminUsers,
  useMe,
} from "../hooks.ts";
import type { AuthUser, Role } from "../types.ts";

export interface UserManagementPanelProps {
  className?: string;
}

/** Admin panel: list, create, edit, disable and delete users. */
export function UserManagementPanel({ className }: UserManagementPanelProps) {
  const { data: users, isLoading, error } = useAdminUsers();
  const { data: me } = useMe();
  const createUser = useAdminCreateUser();
  const updateUser = useAdminUpdateUser();
  const deleteUser = useAdminDeleteUser();

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("user");
  const [formError, setFormError] = useState<string | null>(null);

  const handleCreate = (event: FormEvent) => {
    event.preventDefault();
    setFormError(null);
    createUser.mutate(
      { username, password: password || undefined, role },
      {
        onSuccess: () => {
          setUsername("");
          setPassword("");
          setRole("user");
        },
        onError: (err) => setFormError(err.message),
      }
    );
  };

  const handleResetPassword = (user: AuthUser) => {
    // eslint-disable-next-line no-alert
    const newPassword = window.prompt(`New password for ${user.username}:`);
    if (!newPassword) {
      return;
    }
    updateUser.mutate(
      { id: user.id, input: { password: newPassword } },
      { onError: (err) => setFormError(err.message) }
    );
  };

  const handleDelete = (user: AuthUser) => {
    // eslint-disable-next-line no-alert
    if (!window.confirm(`Delete user ${user.username}?`)) {
      return;
    }
    deleteUser.mutate(user.id, { onError: (err) => setFormError(err.message) });
  };

  return (
    <section className={cx("goauth-panel", className)}>
      <h3 className="goauth-panel-title">Users</h3>

      {error ? <div className="goauth-error">{error.message}</div> : null}
      {formError ? <div className="goauth-error">{formError}</div> : null}

      {isLoading ? (
        <p className="goauth-muted">Loading…</p>
      ) : (
        <table className="goauth-table">
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Status</th>
              <th>Login methods</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {(users ?? []).map((user) => (
              <tr className={user.disabled ? "goauth-row-disabled" : undefined} key={user.id}>
                <td>
                  {user.username}
                  {me && me.id === user.id ? (
                    <span className="goauth-muted"> (you)</span>
                  ) : null}
                </td>
                <td>
                  <select
                    onChange={(e) =>
                      updateUser.mutate(
                        { id: user.id, input: { role: e.target.value as Role } },
                        { onError: (err) => setFormError(err.message) }
                      )
                    }
                    value={user.role}
                  >
                    <option value="user">user</option>
                    <option value="admin">admin</option>
                  </select>
                </td>
                <td>{user.disabled ? "disabled" : "active"}</td>
                <td className="goauth-muted">
                  {[
                    user.hasPassword ? "password" : null,
                    user.passkeyCount > 0 ? `${user.passkeyCount} passkey(s)` : null,
                    user.oidcLinked ? "oidc" : null,
                  ]
                    .filter(Boolean)
                    .join(", ") || "none"}
                </td>
                <td className="goauth-actions">
                  <button
                    className="goauth-button"
                    onClick={() => handleResetPassword(user)}
                    type="button"
                  >
                    Reset password
                  </button>
                  <button
                    className="goauth-button"
                    onClick={() =>
                      updateUser.mutate(
                        { id: user.id, input: { disabled: !user.disabled } },
                        { onError: (err) => setFormError(err.message) }
                      )
                    }
                    type="button"
                  >
                    {user.disabled ? "Enable" : "Disable"}
                  </button>
                  <button
                    className="goauth-button goauth-button-danger"
                    disabled={me?.id === user.id}
                    onClick={() => handleDelete(user)}
                    type="button"
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <form className="goauth-inline-form" onSubmit={handleCreate}>
        <input
          autoCapitalize="none"
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Username"
          required
          value={username}
        />
        <input
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password (min 8 chars)"
          type="password"
          value={password}
        />
        <select onChange={(e) => setRole(e.target.value as Role)} value={role}>
          <option value="user">user</option>
          <option value="admin">admin</option>
        </select>
        <button
          className="goauth-button goauth-button-primary"
          disabled={createUser.isPending}
          type="submit"
        >
          Create user
        </button>
      </form>
    </section>
  );
}

function cx(...parts: Array<string | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
