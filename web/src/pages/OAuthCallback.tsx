import { Link, useSearch } from "@tanstack/react-router";
import Navbar from "../components/Navbar";

const errorMessages: Record<string, string> = {
  signin_failed:
    "Unable to complete sign-in. If you already have an account, try logging in with your email and password, or use a different Google account.",
  email_not_verified:
    "Your Google account email is not verified. Please verify your email with Google and try again.",
  expired: "Your sign-in session has expired. Please try again.",
  provider_not_found: "The requested authentication provider is not available.",
  connect_email_mismatch:
    "The Google account email does not match your account email. Please use the Google account associated with your Agent Vault email.",
  already_connected:
    "This Google account is already connected to your account.",
  connect_failed: "Failed to connect your Google account. Please try again.",
  domain_not_allowed:
    "Your email domain is not allowed for signup. Please use an email address from an approved domain.",
  owner_required:
    "The instance owner must register with email and password first before OAuth login is available.",
};

export default function OAuthCallback() {
  const { error } = useSearch({ from: "/oauth/callback" }) as { error?: string };

  const message =
    error && errorMessages[error]
      ? errorMessages[error]
      : "Something went wrong during sign-in. Please try again.";

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar />
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="flex flex-col items-center w-full">
          <div className="bg-surface rounded-2xl w-full max-w-[480px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
            <div className="flex flex-col items-center text-center">
              <div className="w-16 h-16 rounded-2xl bg-danger/10 flex items-center justify-center mb-6">
                <svg
                  className="w-8 h-8 text-danger"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <circle cx="12" cy="12" r="10" />
                  <line x1="15" y1="9" x2="9" y2="15" />
                  <line x1="9" y1="9" x2="15" y2="15" />
                </svg>
              </div>
              <h2 className="text-2xl font-semibold text-text mb-2">
                Sign-in Failed
              </h2>
              <p className="text-text-muted text-[15px] mb-8">{message}</p>
              <Link
                to="/login"
                className="w-full py-3.5 px-4 bg-primary text-primary-text rounded-lg text-[15px] font-semibold transition-colors flex items-center justify-center gap-2 hover:bg-primary-hover no-underline"
              >
                Back to Login
                <svg
                  className="w-4 h-4"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <line x1="5" y1="12" x2="19" y2="12" />
                  <polyline points="12 5 19 12 12 19" />
                </svg>
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
