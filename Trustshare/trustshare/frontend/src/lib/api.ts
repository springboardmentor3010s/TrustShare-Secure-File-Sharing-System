import axios, { AxiosError, InternalAxiosRequestConfig } from "axios";

const ACCESS_KEY = "ts_access_token";
const REFRESH_KEY = "ts_refresh_token";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(ACCESS_KEY);
}

export function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(REFRESH_KEY);
}

export function setTokens(access: string, refresh: string): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(ACCESS_KEY, access);
  localStorage.setItem(REFRESH_KEY, refresh);
}

export function clearTokens(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
}

// Always uses relative /api/v1 — proxied cleanly by Next.js to FastAPI in dev, Docker, and cloud previews
export const api = axios.create({
  baseURL: "/api/v1",
  timeout: 60000,
});

api.interceptors.request.use((config: InternalAxiosRequestConfig) => {
  const token = getAccessToken();
  if (token && config.headers) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let refreshPromise: Promise<string | null> | null = null;

api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as (InternalAxiosRequestConfig & { _retry?: boolean }) | undefined;
    const isAuthRoute = original?.url?.startsWith("/auth/login") ||
      original?.url?.startsWith("/auth/register") ||
      original?.url?.startsWith("/auth/refresh") ||
      original?.url?.startsWith("/auth/mfa/verify-login");

    if (error.response?.status === 401 && original && !original._retry && !isAuthRoute) {
      const refresh = getRefreshToken();
      if (!refresh) {
        clearTokens();
        return Promise.reject(error);
      }

      original._retry = true;
      if (!refreshPromise) {
        refreshPromise = axios
          .post("/api/v1/auth/refresh", { refresh_token: refresh })
          .then((res) => {
            const { access_token, refresh_token } = res.data;
            if (access_token && refresh_token) {
              setTokens(access_token, refresh_token);
              return access_token as string;
            }
            clearTokens();
            return null;
          })
          .catch(() => {
            clearTokens();
            return null;
          })
          .finally(() => {
            refreshPromise = null;
          });
      }

      const newAccess = await refreshPromise;
      if (newAccess && original.headers) {
        original.headers.Authorization = `Bearer ${newAccess}`;
        return api(original);
      }
    }
    return Promise.reject(error);
  }
);

export function extractApiError(err: unknown, fallback = "Something went wrong."): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      return detail.map((d) => d?.msg || JSON.stringify(d)).join("; ");
    }
    if (err.message) return err.message;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}

export async function downloadAuthenticatedFile(
  fileId: string,
  filename: string,
  version?: number
): Promise<void> {
  const params = version ? { version } : undefined;
  const res = await api.get(`/files/${fileId}/download`, {
    params,
    responseType: "blob",
  });
  const blobUrl = window.URL.createObjectURL(res.data);
  const a = document.createElement("a");
  a.href = blobUrl;
  a.download = version ? `v${version}_${filename}` : filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.URL.revokeObjectURL(blobUrl);
}
