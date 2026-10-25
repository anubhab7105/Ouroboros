import { endpoints } from '@/lib/api';
import { get, post } from '@/lib/apiClient';
import type { CurrentUser, LoginRequest, LoginResponse, PasswordChangeRequest } from '@/types/auth';
import type { MessageResponse } from '@/types/common';

/**
 * Auth API calls.
 *
 * Nothing here logs its arguments. `login` receives a plaintext password, and
 * a well-meaning debug line in this file would put it in the browser console
 * and in any session recording.
 */

export async function login(credentials: LoginRequest): Promise<LoginResponse> {
  // `identifier` accepts a username or an email address; the server decides
  // which it is, so the client does not try to tell them apart.
  return post<LoginResponse>(endpoints.auth.login(), credentials);
}

export async function fetchCurrentUser(): Promise<CurrentUser> {
  return get<CurrentUser>(endpoints.auth.me());
}

export async function changePassword(body: PasswordChangeRequest): Promise<MessageResponse> {
  return post<MessageResponse>(endpoints.auth.changePassword(), body);
}
