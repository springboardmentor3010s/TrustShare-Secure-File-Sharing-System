"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  Database,
  KeyRound,
  Lock,
  ShieldCheck,
  UserCheck,
} from "lucide-react";
import { api, extractApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";

const DEMO_ACCOUNTS = [
  { role: "Admin", email: "admin@trustshare.dev", pass: "Admin@1234", desc: "Full vault + RBAC + all logs" },
  { role: "Manager", email: "manager@trustshare.dev", pass: "Manager@1234", desc: "2 GB vault + org audit read" },
  { role: "Member", email: "member@trustshare.dev", pass: "Member@1234", desc: "Standard encrypted upload" },
  { role: "Guest", email: "guest@trustshare.dev", pass: "Guest@1234", desc: "Read-only shared access" },
];

export default function LoginPage() {
  const { user, loading, login, verifyMfaLogin } = useAuth();
  const router = useRouter();

  const [email, setEmail] = useState("admin@trustshare.dev");
  const [password, setPassword] = useState("Admin@1234");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  // Forgot password modal toggle
  const [resetMode, setResetMode] = useState(false);
  const [resetToken, setResetToken] = useState("");
  const [newPassword, setNewPassword] = useState("");

  useEffect(() => {
    if (!loading && user) router.replace("/dashboard");
  }, [loading, user, router]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setInfo(null);
    try {
      const res = await login(email.trim(), password);
      if (res.mfa_required && res.mfa_token) {
        setMfaToken(res.mfa_token);
      } else {
        router.push("/dashboard");
      }
    } catch (err) {
      setError(extractApiError(err, "Authentication failed."));
    } finally {
      setSubmitting(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaToken) return;
    setSubmitting(true);
    setError(null);
    try {
      await verifyMfaLogin(mfaToken, mfaCode.trim());
      router.push("/dashboard");
    } catch (err) {
      setError(extractApiError(err, "MFA verification failed."));
      setMfaToken(null);
      setMfaCode("");
    } finally {
      setSubmitting(false);
    }
  };

  const handleRequestReset = async () => {
    setError(null);
    setInfo(null);
    try {
      const res = await api.post("/auth/password/forgot", { email: email.trim() });
      if (res.data.dev_reset_token) {
        setResetToken(res.data.dev_reset_token);
        setInfo("Dev-mode recovery token generated and auto-filled below (15-min Redis TTL).");
      } else {
        setInfo(res.data.message);
      }
    } catch (err) {
      setError(extractApiError(err));
    }
  };

  const handleCompleteReset = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const res = await api.post("/auth/password/reset", {
        reset_token: resetToken.trim(),
        new_password: newPassword,
      });
      setInfo(res.data.message);
      setPassword(newPassword);
      setResetMode(false);
      setResetToken("");
      setNewPassword("");
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setSubmitting(false);
    }
  };

  const handleOAuthCheck = async (provider: "google" | "github") => {
    setError(null);
    setInfo(null);
    try {
      const res = await api.get(`/auth/oauth/${provider}/authorize`);
      if (res.data.configured) {
        window.location.href = res.data.authorization_url;
      } else {
        setInfo(`OAuth2 (${provider.toUpperCase()}): ${res.data.note}`);
      }
    } catch (err) {
      setError(extractApiError(err));
    }
  };

  return (
    <div className="grid min-h-screen grid-cols-1 lg:grid-cols-12">
      {/* Left Architectural Panel */}
      <div className="hidden flex-col justify-between bg-slate-950 p-10 text-white lg:col-span-5 lg:flex">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-indigo-500 text-white shadow-lg shadow-indigo-500/30">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight">TrustShare</span>
              <span className="ml-2 rounded-full bg-indigo-500/20 px-2 py-0.5 text-[11px] font-medium text-indigo-300 ring-1 ring-indigo-400/30">
                Milestone 1
              </span>
            </div>
          </div>

          <h1 className="mt-12 text-3xl font-semibold leading-tight tracking-tight text-white">
            Encrypted File Sharing &amp; Controlled Digital Collaboration.
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-slate-400">
            Every uploaded document is validated against MIME spoofing, hashed with SHA-256, and
            encrypted server-side with a unique per-file AES-256-GCM envelope key before storage.
          </p>

          <div className="mt-8 space-y-4">
            <div className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
              <Lock className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
              <div>
                <p className="text-sm font-medium text-slate-100">AES-256-GCM Envelope Storage</p>
                <p className="mt-0.5 text-xs text-slate-400">
                  64 KiB streaming AEAD chunks; DEKs wrapped under root KEK so raw keys never persist.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
              <UserCheck className="mt-0.5 h-4 w-4 shrink-0 text-indigo-400" />
              <div>
                <p className="text-sm font-medium text-slate-100">JWT + Refresh Rotation + TOTP MFA + RBAC</p>
                <p className="mt-0.5 text-xs text-slate-400">
                  Four enforced tiers (Admin, Manager, Member, Guest) with Redis session revocation.
                </p>
              </div>
            </div>
            <div className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/70 p-4">
              <Database className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
              <div>
                <p className="text-sm font-medium text-slate-100">Polyglot Data Layer</p>
                <p className="mt-0.5 text-xs text-slate-400">
                  PostgreSQL metadata &amp; versions · MongoDB immutable audit logs · Redis sessions &amp; rate limits.
                </p>
              </div>
            </div>
          </div>
        </div>

        <p className="text-xs text-slate-500">
          FastAPI · Next.js · TypeScript · Tailwind · PostgreSQL · MongoDB · Redis
        </p>
      </div>

      {/* Right Auth Form */}
      <div className="flex items-center justify-center bg-slate-50 p-6 lg:col-span-7 lg:p-12">
        <div className="w-full max-w-md space-y-6">
          <div className="flex items-center gap-2.5 lg:hidden">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-600 text-white">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <span className="text-lg font-bold text-slate-900">TrustShare</span>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-7 shadow-sm">
            {mfaToken ? (
              <form onSubmit={handleMfaSubmit} className="space-y-4">
                <div className="flex items-center gap-2 text-indigo-600">
                  <KeyRound className="h-5 w-5" />
                  <h2 className="text-lg font-semibold text-slate-900">Two-Factor Verification</h2>
                </div>
                <p className="text-xs text-slate-500">
                  Enter the 6-digit TOTP code from your authenticator app to finish signing in.
                </p>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  maxLength={6}
                  autoFocus
                  required
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="000000"
                  className="w-full rounded-xl border border-slate-300 px-4 py-3 text-center font-mono text-xl tracking-[0.4em] text-slate-900 focus:border-indigo-500 focus:outline-none"
                />
                {error && <p className="rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700">{error}</p>}
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      setMfaToken(null);
                      setMfaCode("");
                    }}
                    className="flex-1 rounded-xl border border-slate-300 py-2.5 text-sm font-medium text-slate-700 hover:bg-slate-50"
                  >
                    Back
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="flex-1 rounded-xl bg-indigo-600 py-2.5 text-sm font-semibold text-white hover:bg-indigo-700"
                  >
                    {submitting ? "Verifying..." : "Verify Code"}
                  </button>
                </div>
              </form>
            ) : resetMode ? (
              <form onSubmit={handleCompleteReset} className="space-y-4">
                <h2 className="text-lg font-semibold text-slate-900">Password Recovery</h2>
                <p className="text-xs text-slate-500">
                  Generate a single-use 15-minute Redis reset token and set a new strong password.
                </p>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-700">Account Email</label>
                  <div className="flex gap-2">
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm"
                    />
                    <button
                      type="button"
                      onClick={handleRequestReset}
                      className="shrink-0 rounded-lg bg-slate-900 px-3 py-2 text-xs font-semibold text-white hover:bg-slate-800"
                    >
                      Get Token
                    </button>
                  </div>
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-700">Recovery Token</label>
                  <input
                    type="text"
                    required
                    value={resetToken}
                    onChange={(e) => setResetToken(e.target.value)}
                    placeholder="Paste recovery token..."
                    className="w-full rounded-lg border border-slate-300 px-3 py-2 font-mono text-xs"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-slate-700">New Password</label>
                  <input
                    type="password"
                    required
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Min 8 chars, upper, lower, digit, symbol"
                    className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
                  />
                </div>
                {info && <p className="rounded-lg bg-indigo-50 px-3 py-2 text-xs text-indigo-700">{info}</p>}
                {error && <p className="rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700">{error}</p>}
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setResetMode(false)}
                    className="flex-1 rounded-lg border border-slate-300 py-2 text-sm font-medium text-slate-700"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={submitting}
                    className="flex-1 rounded-lg bg-indigo-600 py-2 text-sm font-semibold text-white hover:bg-indigo-700"
                  >
                    Reset Password
                  </button>
                </div>
              </form>
            ) : (
              <>
                <div>
                  <h2 className="text-xl font-semibold text-slate-900">Sign in to TrustShare</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Access your encrypted workspace and role-governed repository.
                  </p>
                </div>

                <form onSubmit={handleLogin} className="mt-5 space-y-4">
                  <div>
                    <label className="mb-1 block text-xs font-medium text-slate-700">Email address</label>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full rounded-xl border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 focus:border-indigo-500 focus:outline-none"
                    />
                  </div>
                  <div>
                    <div className="mb-1 flex items-center justify-between">
                      <label className="text-xs font-medium text-slate-700">Password</label>
                      <button
                        type="button"
                        onClick={() => setResetMode(true)}
                        className="text-xs font-medium text-indigo-600 hover:text-indigo-700"
                      >
                        Forgot password?
                      </button>
                    </div>
                    <input
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full rounded-xl border border-slate-300 px-3.5 py-2.5 text-sm text-slate-900 focus:border-indigo-500 focus:outline-none"
                    />
                  </div>

                  {error && (
                    <p className="rounded-lg bg-rose-50 px-3 py-2 text-xs font-medium text-rose-700">
                      {error}
                    </p>
                  )}
                  {info && (
                    <p className="rounded-lg bg-indigo-50 px-3 py-2 text-xs font-medium text-indigo-700">
                      {info}
                    </p>
                  )}

                  <button
                    type="submit"
                    disabled={submitting}
                    className="flex w-full items-center justify-center gap-2 rounded-xl bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white shadow-xs hover:bg-indigo-700 disabled:opacity-60"
                  >
                    <span>{submitting ? "Authenticating..." : "Sign In Securely"}</span>
                    <ArrowRight className="h-4 w-4" />
                  </button>
                </form>

                {/* OAuth2 SSO triggers */}
                <div className="mt-5">
                  <div className="relative flex items-center justify-center">
                    <div className="w-full border-t border-slate-200" />
                    <span className="absolute bg-white px-2.5 text-[11px] text-slate-400">
                      or continue with OAuth2
                    </span>
                  </div>
                  <div className="mt-4 grid grid-cols-2 gap-2.5">
                    <button
                      type="button"
                      onClick={() => handleOAuthCheck("google")}
                      className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    >
                      Google SSO
                    </button>
                    <button
                      type="button"
                      onClick={() => handleOAuthCheck("github")}
                      className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-700 hover:bg-slate-50"
                    >
                      GitHub OAuth2
                    </button>
                  </div>
                </div>

                <p className="mt-5 text-center text-xs text-slate-500">
                  New collaborator?{" "}
                  <Link href="/register" className="font-semibold text-indigo-600 hover:text-indigo-700">
                    Create an account
                  </Link>
                </p>
              </>
            )}
          </div>

          {/* Demo RBAC Quick-Fill Switcher */}
          <div className="rounded-2xl border border-slate-200 bg-white p-4">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              Quick Demo RBAC Accounts (click to fill)
            </p>
            <div className="mt-2.5 grid grid-cols-2 gap-2">
              {DEMO_ACCOUNTS.map((acc) => (
                <button
                  key={acc.role}
                  type="button"
                  onClick={() => {
                    setResetMode(false);
                    setMfaToken(null);
                    setEmail(acc.email);
                    setPassword(acc.pass);
                    setError(null);
                    setInfo(null);
                  }}
                  className={`rounded-xl border p-2.5 text-left transition ${
                    email === acc.email
                      ? "border-indigo-500 bg-indigo-50/60"
                      : "border-slate-200 hover:border-slate-300 hover:bg-slate-50"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-900">{acc.role}</span>
                    <span className="font-mono text-[10px] text-indigo-600">{acc.pass}</span>
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-slate-500">{acc.desc}</p>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
