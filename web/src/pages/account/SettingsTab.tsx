import { useState, useRef, type FormEvent } from "react";
import { useNavigate, useRouteContext } from "@tanstack/react-router";
import type { AuthContext } from "../../router";
import { apiFetch } from "../../lib/api";
import Button from "../../components/Button";
import Input from "../../components/Input";
import FormField from "../../components/FormField";
import Modal from "../../components/Modal";

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

      {/* Change password section */}
      <section className="mb-8">
        <div className="border border-border rounded-xl bg-surface p-5">
          <ChangePasswordForm />
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

function ChangePasswordForm() {
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

    if (!currentPassword) {
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
          current_password: currentPassword,
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
      <h3 className="text-sm font-semibold text-text mb-1">Change Password</h3>
      <p className="text-sm text-text-muted mb-4">
        Enter your current password and choose a new one.
      </p>

      <form onSubmit={handleSubmit} autoComplete="off" className="flex flex-col gap-4 max-w-sm">
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
            Update Password
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
