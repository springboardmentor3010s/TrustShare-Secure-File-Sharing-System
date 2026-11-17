"use client";

import React, { useCallback, useEffect, useState } from "react";
import { ShieldCheck, UserCog } from "lucide-react";
import { api, extractApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { formatBytes, formatDateTime, ROLE_BADGE } from "@/lib/format";
import { User, UserRole } from "@/lib/types";

export default function AdminRbacPage() {
  const { user: currentUser, can } = useAuth();
  const canManage = can("user:manage_roles");

  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [msg, setMsg] = useState<{ type: "ok" | "err"; text: string } | null>(null);

  const loadUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.get<User[]>("/users");
      setUsers(res.data);
    } catch (err) {
      setMsg({ type: "err", text: extractApiError(err) });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const updateRole = async (target: User, role: UserRole) => {
    setMsg(null);
    try {
      await api.patch(`/users/${target.id}`, { role });
      setMsg({ type: "ok", text: `Updated ${target.email} role to ${role.toUpperCase()}.` });
      loadUsers();
    } catch (err) {
      setMsg({ type: "err", text: extractApiError(err) });
    }
  };

  const toggleActive = async (target: User) => {
    setMsg(null);
    try {
      await api.patch(`/users/${target.id}`, { is_active: !target.is_active });
      setMsg({
        type: "ok",
        text: `${target.email} ${target.is_active ? "suspended (sessions revoked)" : "reactivated"}.`,
      });
      loadUsers();
    } catch (err) {
      setMsg({ type: "err", text: extractApiError(err) });
    }
  };

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <UserCog className="h-6 w-6 text-indigo-600" />
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Users &amp; Role-Based Access Control
          </h1>
        </div>
        <p className="mt-0.5 text-sm text-slate-500">
          Assign roles, govern storage quotas, verify MFA posture, and immediately revoke compromised accounts.
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

      <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xs">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-slate-100 bg-slate-50 text-[11px] font-semibold uppercase tracking-wider text-slate-500">
              <tr>
                <th className="px-5 py-3">User</th>
                <th className="px-4 py-3">Role</th>
                <th className="px-4 py-3">MFA</th>
                <th className="px-4 py-3">Storage Usage</th>
                <th className="px-4 py-3">Last Login</th>
                <th className="px-5 py-3 text-right">Status / Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {loading ? (
                <tr>
                  <td colSpan={6} className="px-5 py-10 text-center text-slate-400">
                    Loading directory...
                  </td>
                </tr>
              ) : (
                users.map((u) => {
                  const isSelf = u.id === currentUser?.id;
                  return (
                    <tr key={u.id} className="hover:bg-slate-50/70">
                      <td className="px-5 py-3.5">
                        <p className="font-semibold text-slate-900">{u.full_name}</p>
                        <p className="text-slate-500">{u.email}</p>
                      </td>
                      <td className="px-4 py-3.5">
                        {canManage && !isSelf ? (
                          <select
                            value={u.role}
                            onChange={(e) => updateRole(u, e.target.value as UserRole)}
                            className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs font-semibold text-slate-800"
                          >
                            <option value="admin">ADMIN</option>
                            <option value="manager">MANAGER</option>
                            <option value="member">MEMBER</option>
                            <option value="guest">GUEST</option>
                          </select>
                        ) : (
                          <span
                            className={`rounded-full px-2.5 py-0.5 text-[10px] font-semibold uppercase ${
                              ROLE_BADGE[u.role]
                            }`}
                          >
                            {u.role}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3.5">
                        {u.mfa_enabled ? (
                          <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2 py-0.5 font-medium text-emerald-700">
                            <ShieldCheck className="h-3 w-3" /> TOTP Active
                          </span>
                        ) : (
                          <span className="text-slate-400">Off</span>
                        )}
                      </td>
                      <td className="px-4 py-3.5 font-mono text-slate-700">
                        {formatBytes(u.storage_used_bytes)} / {formatBytes(u.storage_quota_bytes)}
                      </td>
                      <td className="px-4 py-3.5 text-slate-500">
                        {formatDateTime(u.last_login_at)}
                      </td>
                      <td className="px-5 py-3.5 text-right">
                        {canManage && !isSelf ? (
                          <button
                            onClick={() => toggleActive(u)}
                            className={`rounded-lg px-3 py-1 font-semibold ${
                              u.is_active
                                ? "border border-rose-200 bg-rose-50 text-rose-700 hover:bg-rose-100"
                                : "border border-emerald-200 bg-emerald-50 text-emerald-700 hover:bg-emerald-100"
                            }`}
                          >
                            {u.is_active ? "Suspend" : "Reactivate"}
                          </button>
                        ) : (
                          <span className="rounded-full bg-emerald-50 px-2.5 py-0.5 font-medium text-emerald-700">
                            {u.is_active ? "Active" : "Suspended"}
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
