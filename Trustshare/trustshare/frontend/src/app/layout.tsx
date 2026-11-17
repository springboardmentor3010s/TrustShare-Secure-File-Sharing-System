import type { Metadata } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth-context";

export const metadata: Metadata = {
  title: "TrustShare — Encrypted File Sharing & Collaboration",
  description:
    "Server-side AES-256-GCM envelope-encrypted document vault with RBAC, TOTP MFA, file versioning, and immutable audit logging.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
