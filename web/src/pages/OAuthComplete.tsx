import { useSearch } from "@tanstack/react-router";
import Navbar from "../components/Navbar";

export default function OAuthComplete() {
  const search = useSearch({ strict: false }) as Record<string, string>;
  const status = search.status ?? "error";
  const message = search.message ?? "";
  const isSuccess = status === "success";

  return (
    <div className="min-h-screen w-full flex flex-col bg-bg">
      <Navbar />
      <div className="flex-1 flex items-center justify-center p-6">
        <div className="bg-surface rounded-2xl w-full max-w-[480px] p-10 shadow-[0_1px_3px_rgba(0,0,0,0.08),0_8px_24px_rgba(0,0,0,0.04)]">
          <div className="flex flex-col items-center text-center">
            <div className={`w-16 h-16 rounded-2xl flex items-center justify-center mb-6 ${
              isSuccess ? "bg-success/10" : "bg-danger/10"
            }`}>
              {isSuccess ? (
                <svg className="w-8 h-8 text-success" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                  <polyline points="22 4 12 14.01 9 11.01" />
                </svg>
              ) : (
                <svg className="w-8 h-8 text-danger" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="15" y1="9" x2="9" y2="15" />
                  <line x1="9" y1="9" x2="15" y2="15" />
                </svg>
              )}
            </div>
            <h2 className="text-2xl font-semibold text-text mb-2">
              {isSuccess ? "Connected" : "Connection Failed"}
            </h2>
            <p className="text-text-muted text-[15px]">
              {isSuccess
                ? "OAuth authorization complete. You can close this tab and return to the previous page."
                : message || "Something went wrong during the OAuth flow. Please try again."}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
