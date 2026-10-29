import type {
  AuthConfig,
  AuthSettings,
  AuthUser,
  CreateUserInput,
  OidcProviderAdmin,
  OidcProviderInput,
  Passkey,
  UpdateProfileInput,
  UpdateUserInput,
} from "./types.ts";

export class AuthApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "AuthApiError";
    this.status = status;
  }
}

/** Ceiling on a single request so a wedged endpoint errors out instead of
 * leaving callers (e.g. the login page) pending forever. */
const REQUEST_TIMEOUT_MS = 30_000;

async function request<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "TimeoutError") {
      throw new AuthApiError(
        0,
        `request to ${path} timed out after ${REQUEST_TIMEOUT_MS / 1000}s`
      );
    }
    throw error;
  }
  if (!response.ok) {
    let message = response.statusText || `request failed (${response.status})`;
    try {
      const payload = (await response.json()) as { message?: string };
      if (payload.message) {
        message = payload.message;
      }
    } catch {
      // non-JSON error body
    }
    throw new AuthApiError(response.status, message);
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

/**
 * Typed client for the goauth REST endpoints. `basePath` must match the Echo
 * group goauth is mounted at (default "/auth").
 */
export class AuthClient {
  readonly basePath: string;

  constructor(basePath = "/auth") {
    this.basePath = basePath.replace(/\/$/, "");
  }

  getConfig(): Promise<AuthConfig> {
    return request("GET", `${this.basePath}/config`);
  }

  login(identifier: string, password: string): Promise<AuthUser> {
    return request("POST", `${this.basePath}/login`, { identifier, password });
  }

  logout(): Promise<void> {
    return request("POST", `${this.basePath}/logout`);
  }

  /** Returns the logged-in user or null when unauthenticated. */
  async me(): Promise<AuthUser | null> {
    try {
      return await request<AuthUser>("GET", `${this.basePath}/me`);
    } catch (error) {
      if (error instanceof AuthApiError && error.status === 401) {
        return null;
      }
      throw error;
    }
  }

  changePassword(currentPassword: string, newPassword: string): Promise<void> {
    return request("POST", `${this.basePath}/password`, {
      currentPassword,
      newPassword,
    });
  }

  updateProfile(input: UpdateProfileInput): Promise<AuthUser> {
    return request("PATCH", `${this.basePath}/me`, input);
  }

  devLogin(): Promise<AuthUser> {
    return request("POST", `${this.basePath}/dev/login`);
  }

  /** URL that starts the OIDC redirect flow for a provider. */
  oidcStartUrl(providerId: number, next?: string): string {
    const url = `${this.basePath}/oidc/${providerId}/start`;
    return next ? `${url}?next=${encodeURIComponent(next)}` : url;
  }

  // --- Passkeys ---

  async passkeyLogin(): Promise<AuthUser> {
    assertWebAuthnSupport();
    const options = await request<{ publicKey: unknown }>(
      "POST",
      `${this.basePath}/passkey/login/begin`
    );
    const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
      options.publicKey as PublicKeyCredentialRequestOptionsJSON
    );
    const credential = (await navigator.credentials.get({
      publicKey,
    })) as PublicKeyCredential | null;
    if (!credential) {
      throw new AuthApiError(400, "passkey login was cancelled");
    }
    return request("POST", `${this.basePath}/passkey/login/finish`, credential.toJSON());
  }

  async passkeyRegister(name: string): Promise<Passkey> {
    assertWebAuthnSupport();
    const options = await request<{ publicKey: unknown }>(
      "POST",
      `${this.basePath}/passkey/register/begin`
    );
    const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
      options.publicKey as PublicKeyCredentialCreationOptionsJSON
    );
    const credential = (await navigator.credentials.create({
      publicKey,
    })) as PublicKeyCredential | null;
    if (!credential) {
      throw new AuthApiError(400, "passkey registration was cancelled");
    }
    return request(
      "POST",
      `${this.basePath}/passkey/register/finish?name=${encodeURIComponent(name)}`,
      credential.toJSON()
    );
  }

  listPasskeys(): Promise<Passkey[]> {
    return request("GET", `${this.basePath}/passkeys`);
  }

  deletePasskey(id: number): Promise<void> {
    return request("DELETE", `${this.basePath}/passkeys/${id}`);
  }

  // --- Admin ---

  adminListUsers(): Promise<AuthUser[]> {
    return request("GET", `${this.basePath}/admin/users`);
  }

  adminCreateUser(input: CreateUserInput): Promise<AuthUser> {
    return request("POST", `${this.basePath}/admin/users`, input);
  }

  adminUpdateUser(id: number, input: UpdateUserInput): Promise<AuthUser> {
    return request("PATCH", `${this.basePath}/admin/users/${id}`, input);
  }

  adminDeleteUser(id: number): Promise<void> {
    return request("DELETE", `${this.basePath}/admin/users/${id}`);
  }

  adminListOidcProviders(): Promise<OidcProviderAdmin[]> {
    return request("GET", `${this.basePath}/admin/oidc`);
  }

  adminCreateOidcProvider(input: OidcProviderInput): Promise<OidcProviderAdmin> {
    return request("POST", `${this.basePath}/admin/oidc`, input);
  }

  adminUpdateOidcProvider(
    id: number,
    input: OidcProviderInput
  ): Promise<OidcProviderAdmin> {
    return request("PATCH", `${this.basePath}/admin/oidc/${id}`, input);
  }

  adminDeleteOidcProvider(id: number): Promise<void> {
    return request("DELETE", `${this.basePath}/admin/oidc/${id}`);
  }

  adminGetSettings(): Promise<AuthSettings> {
    return request("GET", `${this.basePath}/admin/settings`);
  }

  adminUpdateSettings(settings: AuthSettings): Promise<AuthSettings> {
    return request("PUT", `${this.basePath}/admin/settings`, settings);
  }
}

function assertWebAuthnSupport(): void {
  if (
    typeof PublicKeyCredential === "undefined" ||
    typeof PublicKeyCredential.parseCreationOptionsFromJSON !== "function"
  ) {
    throw new AuthApiError(400, "this browser does not support passkeys");
  }
}

/** Default client instance mounted at /auth. */
export const defaultAuthClient = new AuthClient();
