/** Auth types, mirroring `app/api/v1/endpoints/auth.py`. */

export type UserRole = 'ADMIN' | 'ANALYST' | 'SENIOR_INVESTIGATOR' | 'AUDITOR';

export interface LoginRequest {
  /** A username *or* an email address. The server accepts either. */
  identifier: string;
  password: string;
}

/**
 * The capability booleans `/auth/me` returns.
 *
 * These are the server's own convenience flags for gating the interface, one
 * per action that is not available to every signed-in user. They are not a
 * security control — each protected endpoint re-resolves the real permission
 * from the role on every request — but they are the authority on what to
 * render, because a deployment can widen or narrow any of them through
 * settings and these reflect the settings actually in force.
 *
 * Note what is absent: there is no capability for reading accounts,
 * transactions, alerts, cases, complaints or the network. Those are granted to
 * every role, so an active user can read them and `canRead` says so.
 */
export interface Capabilities {
  read_dashboard: boolean;
  run_analysis: boolean;
  triage_alerts: boolean;
  assign_alerts: boolean;
  escalate_alerts: boolean;
  create_case: boolean;
  assign_case: boolean;
  close_case: boolean;
  reopen_case: boolean;
  add_case_note: boolean;
  add_case_evidence: boolean;
  remove_case_evidence: boolean;
  read_audit: boolean;
  export_audit: boolean;
  manage_users: boolean;
  read_config: boolean;
  write_config: boolean;
  run_ingestion: boolean;
  train_model: boolean;
  evaluate_model: boolean;
  generate_report: boolean;
  download_report: boolean;
  /** The raw complaint narrative is a victim's own account of events. */
  read_complaint_narrative: boolean;
}

export type CapabilityName = keyof Capabilities;

export interface CurrentUser {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
  role: string;
  /** The server's label for the role. Preferred over a local translation. */
  role_display_name: string;
  is_active: boolean;
  must_change_password: boolean;
  last_login_at?: string | null;
  capabilities: Partial<Capabilities> & Record<string, boolean>;
}

/**
 * A successful login.
 *
 * There is no `expires_at`: the server sends `issued_at` and `expires_in`
 * seconds, and the client computes the expiry. Doing the arithmetic locally
 * against the *client's* clock would drift, so it is done against `issued_at`.
 *
 * The signed-in user arrives nested in this response, which means no second
 * round trip to `/auth/me` is needed right after signing in.
 */
export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  issued_at: string;
  user: CurrentUser;
}

export interface PasswordChangeRequest {
  current_password: string;
  new_password: string;
}

/** Users administration, mirroring `app/api/v1/endpoints/users.py`. */
export interface ManagedUser {
  id: string;
  username: string;
  email: string;
  full_name?: string | null;
  role: string;
  role_display_name: string;
  is_active: boolean;
  must_change_password: boolean;
  failed_login_count: number;
  /** Set while the account is locked out after repeated failed sign-ins. */
  locked_until?: string | null;
  last_login_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface CreateUserRequest {
  username: string;
  email: string;
  password: string;
  full_name?: string;
  role?: UserRole;
  must_change_password?: boolean;
}

export interface UpdateUserRequest {
  email?: string;
  full_name?: string;
  role?: UserRole;
  is_active?: boolean;
  must_change_password?: boolean;
}

export interface ResetPasswordRequest {
  new_password: string;
  force_change?: boolean;
}
