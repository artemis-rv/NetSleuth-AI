// Generated from docs/api/openapi-v1.json

export interface User {
  user_id: string;
  username: string;
  role: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
}
