"use client";

import React, { useCallback, useEffect, useState } from "react";
import {
  CheckCircle2,
  KeyRound,
  Laptop,
  Lock,
  Shield,
  Smartphone,
  Trash2,
} from "lucide-react";
import { api, extractApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { formatDateTime } from "@/lib/format";
import { SessionItem } from "@/lib/types";

export default function SecurityAndMfaPage() {
  const { user, refreshUser } = useAuth();

  // MFA setup state
  const [qrDataUri, setQrDataUri] = useState<string | null>(null);
  const [mfaSecret, setMfaSecret] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");

  // Password change state
  const [curPwd, setCurPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");

  // Active sessions
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const loadSessions = useCallback(async () => {
    try {
      const res = await api.get<SessionItem[]>("/auth/sessions");
      setSessions(res.data);
    } catch {
      // ignore
    }
  }, []);

  useEffect(() => {
    loadSessions();
  }, [loadSessions]);

  const startMfaSetup = async () => {
    setMsg(null);
    try {
      const res = await api.post("/auth/mfa/setup");
      setQrDataUri(res.data.qr_code_data_uri);
      setMfaSecret(res.data.secret);
    } catch (err) {
      setMsg({ type: "err", text: extractApiError(err) });
    }
  };

  const confirmEnableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.post("/auth/mfa/enable", { code: mfaCode.trim() });
      setQrDataUri(null);
      setMfaSecret(null);
      setMfaCode("");
      await refreshUser();
      setMsg({ type: "ok", text: "TOTP Multi-Factor Authentication enabled on your account." });
    } catch (err) {
      setMsg({ type: "err", text: extractApiError(err) });
    }
  };

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      await api.post("/auth/mfa/disable", {
        password: disablePassword,
        code: disableCode.trim(),
      });
      setDisablePassword("");
      setDisableCode("");
      await refreshUser();
      setMsg({ type: "ok", text: "Multi-Factor Authentication disabled." });
    } catch (err) {
      setMsg({ type: "err", text: extractApiError(err) });
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      const res = await api.post("/auth/password/change", {
        current_password: curPwd,
        new_password: newPwd,
      });
      setCurPwd("");
      setNewPwd("");
      await loadSessions();
      setMsg({ type: "ok", text: res.data.message });
    } catch (err) {
      setMsg({ type: "err", text: extractApiError(err) });
    }
  };

  const revokeSession = async (id: string) => {
    try {
      await api.delete(`/auth/sessions/${id}`);
      await loadSessions();
      setMsg({ type: "ok", text: "Session revoked in PostgreSQL & Redis." });
    } catch (err) {
      setMsg({ type: "err", text: extractApiError(err) });
    }
  };

  if (!user) return null;

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
          Security, MFA &amp; Active Sessions
        </h1>
        <p className="mt-0.5 text-sm text-slate-500">
          Configure RFC 6238 TOTP two-factor authentication, rotate credentials, and revoke JWT sessions.
        </p>
      </div>

      {msg && (
        <div
          className={`rounded-xl px-4 py-3 text-xs font-medium ${
            msg.type === "ok"
              ? "bg-emerald-50 text-emerald-800 ring-1 ring-emerald-200"
              : "bg-rose-50 text-rose-800 ring-1 ring-rose-200"
          }`}
        >
          {msg.text}
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* TOTP MFA Card */}
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-2xs">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <Smartphone className="h-5 w-5 text-indigo-600" />
              <h2 className="text-base font-semibold text-slate-900">Multi-Factor Auth (TOTP)</h2>
            </div>
            <span
              className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ${
                user.mfa_enabled
                  ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200"
                  : "bg-slate-100 text-slate-600"
              }`}
            >
              {user.mfa_enabled ? "Enabled" : "Not Enabled"}
            </span>
          </div>

          <p className="mt-2 text-xs text-slate-500">
            Protects login with a 30-second 6-digit code (Google Authenticator, Authy, 1Password). Your
            TOTP seed is stored AES-256-GCM encrypted under the root KEK.
          </p>

          {!user.mfa_enabled && !qrDataUri && (
            <button
              onClick={startMfaSetup}
              className="mt-4 rounded-xl bg-indigo-600 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-700"
            >
              Enroll Authenticator App
            </button>
          )}

          {!user.mfa_enabled && qrDataUri && mfaSecret && (
            <form onSubmit={confirmEnableMfa} className="mt-4 space-y-3">
              <div className="flex items-center gap-4 rounded-xl border border-slate-200 bg-slate-50 p-3">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                  src={qrDataUri}
                  alt="TOTP QR code"
                  className="h-28 w-28 rounded-lg border border-slate-200 bg-white"
                />
                <div className="min-w-0 text-xs">
                  <p className="font-medium text-slate-800">Scan QR or enter manual key:</p>
                  <p className="mt-1 break-all rounded bg-white px-2 py-1 font-mono text-[11px] text-indigo-700 ring-1 ring-slate-200">
                    {mfaSecret}
                  </p>
                </div>
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  required
                  maxLength={6}
                  placeholder="Enter 6-digit code"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  className="flex-1 rounded-lg border border-slate-300 px-3 py-2 font-mono text-sm"
                />
                <button
                  type="submit"
                  className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-semibold text-white hover:bg-emerald-700"
                >
                  Verify &amp; Activate
                </button>
              </div>
            </form>
          )}

          {user.mfa_enabled && (
            <form onSubmit={handleDisableMfa} className="mt-4 space-y-2.5 border-t border-slate-100 pt-4">
              <p className="text-xs font-medium text-slate-700">Disable MFA (requires password + TOTP):</p>
              <input
                type="password"
                required
                placeholder="Current password"
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-xs"
              />
              <div className="flex gap-2">
                <input
                  type="text"
                  required
                  maxLength={6}
                  placeholder="6-digit code"
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value)}
                  className="flex-1 rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs"
                />
                <button
                  type="submit"
                  className="rounded-lg bg-rose-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-rose-700"
                >
                  Disable MFA
                </button>
              </div>
            </form>
          )}
        </div>

        {/* Password Rotation Card */}
        <form
          onSubmit={handleChangePassword}
          className="rounded-2xl border border-slate-200 bg-white p-6 shadow-2xs"
        >
          <div className="flex items-center gap-2.5">
            <Lock className="h-5 w-5 text-slate-700" />
            <h2 className="text-base font-semibold text-slate-900">Change Password</h2>
          </div>
          <p className="mt-2 text-xs text-slate-500">
            Hashed with bcrypt (12 rounds). Rotating your password automatically revokes all other open
            sessions.
          </p>
          <div className="mt-4 space-y-3">
            <input
              type="password"
              required
              placeholder="Current password"
              value={curPwd}
              onChange={(e) => setCurPwd(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
            <input
              type="password"
              required
              placeholder="New password (8+ chars, upper, lower, digit, symbol)"
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
            <button
              type="submit"
              className="rounded-xl bg-slate-900 px-4 py-2 text-xs font-semibold text-white hover:bg-slate-800"
            >
              Update Password
            </button>
          </div>
        </form>
      </div>

      {/* Active JWT Sessions */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-2xs">
        <div className="flex items-center gap-2.5">
          <Laptop className="h-5 w-5 text-indigo-600" />
          <h2 className="text-base font-semibold text-slate-900">
            Active Sessions ({sessions.length})
          </h2>
        </div>
        <div className="mt-4 divide-y divide-slate-100">
          {sessions.map((s) => (
            <div key={s.id} className="flex items-center justify-between gap-4 py-3 text-xs">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-slate-900">
                    IP: {s.ip_address || "127.0.0.1"}
                  </span>
                  {s.is_current && (
                    <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 text-[10px] font-semibold text-emerald-700">
                      <CheckCircle2 className="h-3 w-3" /> Current Session
                    </span>
                  )}
                </div>
                <p className="mt-0.5 truncate text-slate-500">
                  {s.user_agent || "Browser / API Client"}
                </p>
                <p className="mt-0.5 text-[11px] text-slate-400">
                  Created {formatDateTime(s.created_at)} · Expires {formatDateTime(s.expires_at)}
                </p>
              </div>
              {!s.is_current && (
                <button
                  onClick={() => revokeSession(s.id)}
                  className="inline-flex items-center gap-1 rounded-lg border border-rose-200 bg-rose-50 px-2.5 py-1.5 font-medium text-rose-700 hover:bg-rose-100"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Revoke
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Effective RBAC Permissions */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-2xs">
        <div className="flex items-center gap-2.5">
          <Shield className="h-5 w-5 text-emerald-600" />
          <h2 className="text-base font-semibold text-slate-900">
            Effective RBAC Scopes (Role: <span className="uppercase text-indigo-600">{user.role}</span>)
          </h2>
        </div>
        <div className="mt-3 flex flex-wrap gap-2">
          {user.permissions.map((perm) => (
            <span
              key={perm}
              className="inline-flex items-center gap-1 rounded-lg bg-slate-100 px-2.5 py-1 font-mono text-xs text-slate-700"
            >
              <KeyRound className="h-3 w-3 text-indigo-500" />
              {perm}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
