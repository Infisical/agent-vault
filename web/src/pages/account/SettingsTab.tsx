import { useState, useRef, type FormEvent } from "react";
import { useNavigate, useRouteContext } from "@tanstack/react-router";
import type { AuthContext } from "../../router";
import { apiFetch } from "../../lib/api";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import Modal from "../../components/Modal";
import { useOAuthProviders } from "../../components/GoogleButton";

export default function AccountSettingsTab() {
  const { auth } = useRouteContext({ from: "/_auth" }) as { auth: AuthContext };

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="mb-6">
        <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
          Settings
        </h2>
        <p className="text-sm text-text-muted">
          Manage your account settings.
        </p>
      </div>

      {/* Authentication methods */}
      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <AuthMethodsSection auth={auth} />
        </div>
      </section>

      {/* Change password section */}
      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <ChangePasswordForm hasPassword={auth.has_password} />
        </div>
      </section>

      {/* Delete account — non-owners only */}
      {!auth.is_owner && (
        <section>
          <DeleteAccountSection email={auth.email} />
        </section>
      )}
    </div>
  );
}

function AuthMethodsSection({ auth }: { auth: AuthContext }) {
  const availableProviders = useOAuthProviders();
  const hasGoogle = auth.oauth_providers.includes("google");
  const googleAvailable = availableProviders.some((p) => p.name === "google");
  const [disconnecting, setDisconnecting] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  async function handleDisconnect() {
    setError("");
    setDisconnecting(true);
    try {
      const resp = await apiFetch("/v1/auth/oauth/google", { method: "DELETE" });
      if (resp.ok) {
        setSuccess("Google account disconnected. Reload the page to see changes.");
      } else {
        const data = await resp.json().catch(() => ({}));
        setError(data.error || "Failed to disconnect.");
      }
    } catch {
      setError("Network error.");
    } finally {
      setDisconnecting(false);
    }
  }

  async function handleConnect() {
    window.location.href = "/v1/auth/oauth/google/connect";
  }

  return (
    <>
      <h3 className="text-sm font-semibold text-text mb-1">Authentication Methods</h3>
      <p className="text-sm text-text-muted mb-4">
        Manage how you sign in to your account.
      </p>

      <div className="flex flex-col gap-3">
        {/* Password */}
        <div className="flex items-center justify-between p-3 bg-bg rounded-lg border border-border">
          <div className="flex items-center gap-3">
            <svg className="w-5 h-5 text-text-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            <div>
              <div className="text-sm font-medium text-text">Password</div>
              <div className="text-xs text-text-muted">
                {auth.has_password ? "Configured" : "Not set"}
              </div>
            </div>
          </div>
          {auth.has_password ? (
            <span className="text-xs text-success font-medium">Active</span>
          ) : (
            <span className="text-xs text-text-dim">Set one below</span>
          )}
        </div>

        {/* Google */}
        {googleAvailable && (
          <div className="flex items-center justify-between p-3 bg-bg rounded-lg border border-border">
            <div className="flex items-center gap-3">
              <svg width="18" height="18" viewBox="0 0 18 18" fill="none" className="flex-shrink-0">
                <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844a4.14 4.14 0 0 1-1.796 2.716v2.259h2.908c1.702-1.567 2.684-3.875 2.684-6.615Z" fill="#4285F4" />
                <path d="M9 18c2.43 0 4.467-.806 5.956-2.18l-2.908-2.259c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 0 0 9 18Z" fill="#34A853" />
                <path d="M3.964 10.71A5.41 5.41 0 0 1 3.682 9c0-.593.102-1.17.282-1.71V4.958H.957A8.997 8.997 0 0 0 0 9c0 1.452.348 2.827.957 4.042l3.007-2.332Z" fill="#FBBC05" />
                <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 0 0 .957 4.958L3.964 7.29C4.672 5.163 6.656 3.58 9 3.58Z" fill="#EA4335" />
              </svg>
              <div>
                <div className="text-sm font-medium text-text">Google</div>
                <div className="text-xs text-text-muted">
                  {hasGoogle ? "Connected" : "Not connected"}
                </div>
              </div>
            </div>
            {hasGoogle ? (
              <Button
                variant="secondary"
                onClick={handleDisconnect}
                loading={disconnecting}
                disabled={!auth.has_password}
                className="!text-xs !py-1 !px-3"
              >
                Disconnect
              </Button>
            ) : (
              <Button
                variant="secondary"
                onClick={handleConnect}
                className="!text-xs !py-1 !px-3"
              >
                Connect
              </Button>
            )}
          </div>
        )}
      </div>

      {!auth.has_password && hasGoogle && (
        <p className="text-xs text-text-dim mt-2">
          Set a password below before disconnecting Google to avoid losing access.
        </p>
      )}

      {error && (
        <div className="mt-3 bg-danger-bg border border-danger/20 rounded-lg p-3 text-sm text-danger">
          {error}
        </div>
      )}
      {success && (
        <div className="mt-3 bg-success-bg border border-success/20 rounded-lg p-3 text-sm text-success">
          {success}
        </div>
      )}
    </>
  );
}

function ChangePasswordForm({ hasPassword }: { hasPassword: boolean }) {
  const navigate = useNavigate();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [formError, setFormError] = useState("");
  const [fieldError, setFieldError] = useState("");
  const [errorField, setErrorField] = useState<"new" | "confirm" | "">("");
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);

  const currentRef = useRef<HTMLInputElement>(null);
  const newRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError("");
    setFieldError("");

    if (hasPassword && !currentPassword) {
      currentRef.current?.focus();
      return;
    }
    if (!newPassword) {
      newRef.current?.focus();
      return;
    }
    if (newPassword.length < 8) {
      setFieldError("Password must be at least 8 characters.");
      setErrorField("new");
      newRef.current?.focus();
      return;
    }
    if (newPassword !== confirmPassword) {
      setFieldError("Passwords do not match.");
      setErrorField("confirm");
      confirmRef.current?.focus();
      return;
    }

    setSubmitting(true);

    try {
      const resp = await apiFetch("/v1/auth/change-password", {
        method: "POST",
        body: JSON.stringify({
          ...(hasPassword ? { current_password: currentPassword } : {}),
          new_password: newPassword,
        }),
      });
      const data = await resp.json();

      if (resp.ok) {
        setSuccess(true);
        setTimeout(() => navigate({ to: "/" }), 1500);
      } else {
        setFormError(data.error || "Failed to change password.");
        setSubmitting(false);
      }
    } catch {
      setFormError("Network error. Please check your connection and try again.");
      setSubmitting(false);
    }
  }

  if (success) {
    return (
      <div className="text-center py-4">
        <div className="w-12 h-12 mx-auto mb-4 rounded-full bg-success-bg flex items-center justify-center">
          <svg className="w-6 h-6 text-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12" />
          </svg>
        </div>
        <h3 className="text-lg font-semibold text-text mb-1">Password changed</h3>
        <p className="text-sm text-text-muted">Redirecting...</p>
      </div>
    );
  }

  return (
    <>
      <h3 className="text-sm font-semibold text-text mb-1">
        {hasPassword ? "Change Password" : "Set Password"}
      </h3>
      <p className="text-sm text-text-muted mb-4">
        {hasPassword
          ? "Enter your current password and choose a new one."
          : "Set a password to enable email/password login and CLI access."}
      </p>

      <form onSubmit={handleSubmit} autoComplete="off" className="flex flex-col gap-4 max-w-sm">
        {hasPassword && (
          <FormField label="Current password">
            <Input
              ref={currentRef}
              type="password"
              placeholder="&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </FormField>
        )}

        <FormField label="New password" error={errorField === "new" ? fieldError : undefined}>
          <Input
            ref={newRef}
            type="password"
            placeholder="At least 8 characters"
            autoComplete="new-password"
            error={errorField === "new"}
            value={newPassword}
            onChange={(e) => { setNewPassword(e.target.value); setFieldError(""); setErrorField(""); }}
          />
        </FormField>

        <FormField label="Confirm new password" error={errorField === "confirm" ? fieldError : undefined}>
          <Input
            ref={confirmRef}
            type="password"
            placeholder="Re-enter new password"
            autoComplete="new-password"
            error={errorField === "confirm"}
            value={confirmPassword}
            onChange={(e) => { setConfirmPassword(e.target.value); setFieldError(""); setErrorField(""); }}
          />
        </FormField>

        {formError && (
          <div className="bg-danger-bg border border-danger/20 rounded-lg p-4 text-sm text-danger">
            {formError}
          </div>
        )}

        <div className="mt-1">
          <Button type="submit" loading={submitting}>
            {hasPassword ? "Update Password" : "Set Password"}
          </Button>
        </div>
      </form>
    </>
  );
}

function DeleteAccountSection({ email }: { email: string }) {
  const navigate = useNavigate();
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [deleteConfirm, setDeleteConfirm] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  async function handleDelete() {
    setDeleting(true);
    setDeleteError("");

    try {
      const resp = await apiFetch("/v1/auth/account", { method: "DELETE" });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setDeleteError(data.error || "Failed to delete account");
        return;
      }
      navigate({ to: "/login" });
    } catch {
      setDeleteError("Network error");
    } finally {
      setDeleting(false);
    }
  }

  return (
    <>
      <div className="border border-danger/20 rounded-xl bg-surface p-5">
        <h3 className="text-sm font-semibold text-danger mb-1">Danger Zone</h3>
        <p className="text-sm text-text-muted mb-4">
          Permanently delete your account and all associated data. This action cannot be undone.
        </p>
        <Button
          variant="secondary"
          onClick={() => setShowDeleteModal(true)}
          className="!text-danger !border-danger/30 hover:!bg-danger-bg"
        >
          Delete account
        </Button>
      </div>

      <Modal
        open={showDeleteModal}
        onClose={() => {
          setShowDeleteModal(false);
          setDeleteConfirm("");
          setDeleteError("");
        }}
        title="Delete account"
        description={`This will permanently delete your account and remove you from all vaults. Type your email to confirm.`}
        footer={
          <>
            <Button variant="secondary" onClick={() => setShowDeleteModal(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleDelete}
              disabled={deleteConfirm !== email}
              loading={deleting}
              className="!bg-danger !text-white hover:!bg-danger/90"
            >
              Delete permanently
            </Button>
          </>
        }
      >
        <FormField label="Email address">
          <Input
            value={deleteConfirm}
            onChange={(e) => {
              setDeleteConfirm(e.target.value);
              setDeleteError("");
            }}
            placeholder={email}
          />
        </FormField>
        {deleteError && (
          <div className="mt-3 bg-danger-bg border border-danger/20 rounded-lg p-4 text-sm text-danger">
            {deleteError}
          </div>
        )}
      </Modal>
    </>
  );
}
