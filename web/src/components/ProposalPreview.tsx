export interface Auth {
  type: string;
  token?: string;
  username?: string;
  password?: string;
  key?: string;
  header?: string;
  prefix?: string;
  headers?: Record<string, string>;
}

export interface Rule {
  action: string;
  host: string;
  description?: string;
  auth?: Auth;
}

export interface CredentialSlot {
  action: string;
  key: string;
  description?: string;
  obtain?: string;
  obtain_instructions?: string;
  has_value?: boolean;
}

export interface ProposalData {
  proposal_id?: number;
  vault?: string;
  status?: string;
  user_message?: string;
  message?: string;
  rules?: Rule[];
  credentials?: CredentialSlot[];
  created_at?: string;
}

/** Parse rules from a JSON string (as stored on proposal rows). */
export function parseRules(rulesJson?: string): Rule[] {
  try {
    if (rulesJson) return JSON.parse(rulesJson) ?? [];
  } catch {
    // ignore
  }
  return [];
}

/** Parse credential slots from a JSON string. */
export function parseCredentials(credentialsJson?: string): CredentialSlot[] {
  try {
    if (credentialsJson) return JSON.parse(credentialsJson) ?? [];
  } catch {
    // ignore
  }
  return [];
}

export const AUTH_TYPE_LABELS: Record<string, string> = {
  bearer: "Bearer token",
  basic: "HTTP Basic Auth",
  "api-key": "API key",
  custom: "Custom headers",
};

function AuthDisplay({ auth }: { auth: Auth }) {
  const label = AUTH_TYPE_LABELS[auth.type] || auth.type;

  return (
    <div className="mt-2 pt-2 border-t border-border">
      <div className="text-[10px] font-semibold text-text-muted uppercase tracking-wider mb-1.5">
        Authentication
      </div>
      <div className="text-xs font-mono text-text mb-1">{label}</div>
      {auth.type === "custom" &&
        auth.headers &&
        Object.keys(auth.headers).length > 0 && (
          <div className="mt-1">
            {Object.entries(auth.headers).map(([header, template]) => (
              <div
                key={header}
                className="flex items-start gap-1.5 text-xs font-mono leading-relaxed"
              >
                <span className="text-text-muted">{header}:</span>
                <span className="text-text break-all">{template}</span>
              </div>
            ))}
          </div>
        )}
    </div>
  );
}

export default function ProposalPreview({ data }: { data: ProposalData }) {
  const setRules = (data.rules ?? []).filter((r) => r.action === "set");
  const deleteRules = (data.rules ?? []).filter((r) => r.action === "delete");
  const credentials = (data.credentials ?? []).filter(
    (s) => s.action === "set" && !s.has_value
  );
  const deleteCredentials = (data.credentials ?? []).filter(
    (s) => s.action === "delete"
  );

  const titleParts: string[] = [];
  if (setRules.length > 0)
    titleParts.push(
      setRules.length === 1
        ? setRules[0].description || setRules[0].host
        : `${setRules.length} services`
    );
  if (deleteRules.length > 0)
    titleParts.push(`remove ${deleteRules.length === 1 ? deleteRules[0].host : `${deleteRules.length} services`}`);

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <div className="w-10 h-10 rounded-xl bg-primary/10 flex items-center justify-center flex-shrink-0">
          <svg className="w-5 h-5 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <polyline points="9 12 12 15 16 10" />
          </svg>
        </div>
        <div>
          <h1 className="text-xl font-semibold text-text leading-tight">
            {titleParts.length > 0
              ? (setRules.length > 0 ? "Connect to " : "") + titleParts.join(" & ")
              : "Policy change"}
          </h1>
        </div>
      </div>

      {(data.user_message || data.message) && (
        <p className="text-text-muted text-[15px] mb-5 leading-relaxed">
          {data.user_message || data.message}
        </p>
      )}

      {setRules.length > 0 && (
        <div className="mb-4">
          <div className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">
            Services requested
          </div>
          <div className="space-y-3">
            {setRules.map((rule, i) => (
              <div key={i} className="bg-bg border border-border rounded-lg p-3">
                <div>
                  <div className="text-[10px] font-semibold text-text-muted uppercase tracking-wider mb-1.5">
                    Host
                  </div>
                  <span className="text-sm text-text font-mono">
                    {rule.host}
                  </span>
                  {rule.description && (
                    <p className="text-xs text-text-muted mt-1">{rule.description}</p>
                  )}
                </div>
                {rule.auth && <AuthDisplay auth={rule.auth} />}
              </div>
            ))}
          </div>
        </div>
      )}

      {deleteRules.length > 0 && (
        <div className="bg-bg rounded-lg border border-danger/20 p-4 mb-4">
          <div className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
            Services to remove
          </div>
          <div className="space-y-1.5">
            {deleteRules.map((rule, i) => (
              <div key={i} className="flex items-center gap-2 text-sm text-text font-mono">
                <svg className="w-3.5 h-3.5 text-danger flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
                {rule.host}
              </div>
            ))}
          </div>
        </div>
      )}

      {credentials.length > 0 && (
        <div className="mb-4">
          <div className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
            Credentials needed
          </div>
          <ul className="bg-bg rounded-lg border border-border p-4 space-y-1.5">
            {credentials.map((s) => (
              <li key={s.key} className="text-sm text-text flex items-start gap-2">
                <svg className="w-3.5 h-3.5 text-text-muted flex-shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <div>
                  <span className="font-mono">{s.key}</span>
                  {s.description && s.description !== s.key && (
                    <p className="text-xs text-text-muted mt-0.5">{s.description}</p>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {deleteCredentials.length > 0 && (
        <div className="bg-bg rounded-lg border border-danger/20 p-4">
          <div className="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
            Credentials to remove
          </div>
          <ul className="space-y-1.5">
            {deleteCredentials.map((s) => (
              <li key={s.key} className="text-sm text-text flex items-center gap-2 font-mono">
                <svg className="w-3.5 h-3.5 text-danger flex-shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
                {s.key}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
