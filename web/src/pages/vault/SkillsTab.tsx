import { useState, useEffect, useMemo } from "react";
import { useVaultParams, LoadingSpinner, ErrorBanner } from "./shared";
import DataTable, { type Column } from "../../components/DataTable";
import Modal from "../../components/Modal";
import Sheet from "../../components/Sheet";
import Button from "../../components/Button";
import Input from "../../components/Input";
import Textarea from "../../components/Textarea";
import FormField from "../../components/FormField";
import DropdownMenu from "../../components/DropdownMenu";
import { apiFetch, apiRequest } from "../../lib/api";

/** Mirrors maxSkillContentChars in internal/server/handle_skills.go. */
const MAX_CONTENT_CHARS = 100_000;

/**
 * Mirrors maxSkillDescriptionChars — the Agent Skills frontmatter limit for a
 * skill's `description`. The `name` limit from that spec (64 characters) is
 * stated in the field tooltip and enforced server-side by broker.ValidateSlug.
 */
const MAX_DESCRIPTION_CHARS = 1024;

/**
 * Character count matching Go's utf8.RuneCountInString, so the number shown
 * against MAX_CONTENT_CHARS is the one the server enforces. String.length
 * would count an astral character such as an emoji as two, so surrogate
 * pairs are collapsed here.
 */
function countChars(text: string): number {
  let chars = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    // High surrogate followed by a low surrogate is one character.
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < text.length) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) i++;
    }
    chars++;
  }
  return chars;
}

interface SkillRow {
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

interface SkillDetail extends SkillRow {
  content: string;
}

interface SkillPayload {
  name: string;
  description: string;
  content: string;
}

type EditingState =
  | { mode: "add" }
  | { mode: "edit"; skill: SkillDetail }
  | null;

export default function SkillsTab() {
  const { vaultName, vaultRole } = useVaultParams();
  const [skills, setSkills] = useState<SkillRow[]>([]);
  const [loading, setLoading] = useState(true);
  // `error` gates the table: it means the list itself could not be loaded.
  // Transient per-row failures go to `actionError`, which shows above the
  // table so a failed action never hides the data.
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  // Opening the edit form needs the markdown body, which the list omits, so
  // this holds a fetched record rather than an index into `skills`.
  const [editing, setEditing] = useState<EditingState>(null);
  const [deleteName, setDeleteName] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const isAdmin = vaultRole === "admin";
  const skillsUrl = `/v1/vaults/${encodeURIComponent(vaultName)}/skills`;
  const skillUrl = (name: string) => `${skillsUrl}/${encodeURIComponent(name)}`;

  useEffect(() => {
    fetchSkills();
  }, []);

  async function fetchSkills() {
    try {
      const resp = await apiFetch(skillsUrl);
      const data = await resp.json();
      if (!resp.ok) {
        setError(data.error || "Failed to load skills.");
        return;
      }
      setSkills(data.skills ?? []);
      setError("");
    } catch {
      setError("Network error.");
    } finally {
      setLoading(false);
    }
  }

  async function openEdit(name: string) {
    setActionError("");
    try {
      const data = await apiRequest<{ skill: SkillDetail }>(skillUrl(name));
      setEditing({ mode: "edit", skill: data.skill });
    } catch {
      // Most likely another admin deleted it; refresh so the row goes away.
      setActionError(`Could not open "${name}". It may have just been deleted.`);
      fetchSkills();
    }
  }

  // Throws ApiError on failure; SkillSheet renders the message.
  async function saveSkill(payload: SkillPayload, oldName?: string) {
    await apiRequest(oldName ? skillUrl(oldName) : skillsUrl, {
      method: oldName ? "PATCH" : "POST",
      body: JSON.stringify(payload),
    });
    await fetchSkills();
  }

  async function handleDelete() {
    if (deleteName === null) return;
    setDeleting(true);
    setDeleteError("");
    try {
      const resp = await apiFetch(skillUrl(deleteName), { method: "DELETE" });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        setDeleteError(data.error || "Failed to delete skill.");
        return;
      }
      await fetchSkills();
      setDeleteName(null);
    } catch {
      setDeleteError("Network error.");
    } finally {
      setDeleting(false);
    }
  }

  const columns: Column<SkillRow>[] = [
    {
      key: "name",
      header: "Name",
      render: (skill) => (
        <span className="text-sm font-mono font-medium text-text">
          {skill.name}
        </span>
      ),
    },
    {
      key: "description",
      header: "Description",
      render: (skill) => (
        <div className="text-sm text-text-muted max-w-[520px] truncate">
          {skill.description || "—"}
        </div>
      ),
    },
    ...(isAdmin
      ? [
          {
            key: "actions",
            header: "",
            align: "right" as const,
            render: (skill: SkillRow) => (
              <DropdownMenu
                items={[
                  { label: "Edit", onClick: () => openEdit(skill.name) },
                  {
                    label: "Delete",
                    onClick: () => setDeleteName(skill.name),
                    variant: "danger" as const,
                  },
                ]}
              />
            ),
          } as Column<SkillRow>,
        ]
      : []),
  ];

  return (
    <div className="p-8 w-full max-w-[960px]">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-[22px] font-semibold text-text tracking-tight mb-1">
            Skills
          </h2>
          <p className="text-sm text-text-muted">
            Markdown instructions for agents working in this vault.
          </p>
        </div>
        {isAdmin && (
          <Button onClick={() => setEditing({ mode: "add" })}>
            <svg
              className="w-4 h-4"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Add skill
          </Button>
        )}
      </div>

      {actionError && (
        <div className="mb-4">
          <ErrorBanner message={actionError} />
        </div>
      )}

      {loading ? (
        <LoadingSpinner />
      ) : error ? (
        <ErrorBanner message={error} />
      ) : (
        <DataTable
          columns={columns}
          data={skills}
          rowKey={(skill) => skill.name}
          emptyTitle="No skills yet"
          emptyDescription="Add a skill to give agents reusable instructions in this vault."
        />
      )}

      {/* Delete confirmation modal */}
      <Modal
        open={deleteName !== null}
        onClose={() => {
          setDeleteName(null);
          setDeleteError("");
        }}
        title="Delete skill"
        description={`Permanently delete "${deleteName}". Agents will no longer receive these instructions.`}
        footer={
          <>
            <Button
              variant="secondary"
              onClick={() => {
                setDeleteName(null);
                setDeleteError("");
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleDelete}
              loading={deleting}
              className="!bg-danger !text-white hover:!bg-danger/90"
            >
              Delete
            </Button>
          </>
        }
      >
        {deleteError && <ErrorBanner message={deleteError} />}
      </Modal>

      {editing && (
        <SkillSheet
          title={editing.mode === "add" ? "Add Skill" : "Edit Skill"}
          initial={editing.mode === "edit" ? editing.skill : undefined}
          onClose={() => setEditing(null)}
          onSave={async (payload) => {
            await saveSkill(
              payload,
              editing.mode === "edit" ? editing.skill.name : undefined
            );
            setEditing(null);
          }}
        />
      )}
    </div>
  );
}

/* -- Add / Edit sheet -- */

function SkillSheet({
  title,
  initial,
  onClose,
  onSave,
}: {
  title: string;
  initial?: SkillDetail;
  onClose: () => void;
  onSave: (payload: SkillPayload) => Promise<void>;
}) {
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [content, setContent] = useState(initial?.content ?? "");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const trimmedName = name.trim();
  // Memoized so typing in Name or Description does not re-count the body.
  const contentChars = useMemo(() => countChars(content), [content]);
  const contentTooLarge = contentChars > MAX_CONTENT_CHARS;
  // Short enough to count on every render. Counted trimmed because the
  // handler trims before validating, so trailing whitespace must not make the
  // form stricter than the server.
  const descriptionChars = countChars(description.trim());
  const descriptionTooLong = descriptionChars > MAX_DESCRIPTION_CHARS;
  // Only presence is gated here, matching ServicesTab: the slug rule lives in
  // the field tooltip and is enforced server-side, so a half-typed name is
  // never flagged mid-keystroke.
  const canSubmit =
    trimmedName !== "" &&
    content.trim() !== "" &&
    !contentTooLarge &&
    !descriptionTooLong &&
    !saving;

  async function handleSubmit() {
    if (!canSubmit) return;
    setSaving(true);
    setError("");
    try {
      await onSave({
        name: trimmedName,
        description: description.trim(),
        content,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save skill.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet
      open
      onClose={onClose}
      eyebrow="Skill"
      title={title}
      widthClass="max-w-[640px]"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={handleSubmit} disabled={!canSubmit} loading={saving}>
            {initial ? "Save" : "Add skill"}
          </Button>
        </>
      }
    >
      {/* Full-height column so Instructions absorbs the slack and its helper
          text and byte counter stay above the footer instead of scrolling
          out of view. */}
      <div className="flex h-full flex-col gap-4">
        {error && <ErrorBanner message={error} />}

        <FormField
          label="Name"
          required
          className="shrink-0"
          tooltip="Slug-style identifier (3–64 chars, lowercase, hyphens). Becomes the skill's directory name on an agent's filesystem."
        >
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. deploy-staging, audit-logs"
            autoFocus
          />
        </FormField>

        <FormField
          label="Description"
          className="shrink-0"
          error={
            descriptionTooLong
              ? `Too long by ${(
                  descriptionChars - MAX_DESCRIPTION_CHARS
                ).toLocaleString()} characters.`
              : undefined
          }
          helperText="A single line telling an agent when to reach for this skill. Shown in the skills table."
        >
          {/* Wraps for room, but stays one line: this becomes a single YAML
              scalar in SKILL.md frontmatter, so Enter is suppressed rather
              than silently folded to a space on save. */}
          <Textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") e.preventDefault();
            }}
            rows={2}
            placeholder="Use when deploying to the staging environment."
            error={descriptionTooLong}
          />
          <p
            className={`mt-2 text-right text-xs ${
              descriptionTooLong ? "text-danger" : "text-text-dim"
            }`}
          >
            {descriptionChars.toLocaleString()} / {MAX_DESCRIPTION_CHARS.toLocaleString()} characters
          </p>
        </FormField>

        <FormField
          label="Instructions"
          required
          className="flex min-h-0 flex-1 flex-col"
          error={
            contentTooLarge
              ? `Too long by ${(
                  contentChars - MAX_CONTENT_CHARS
                ).toLocaleString()} characters.`
              : undefined
          }
          helperText="Markdown. Do not put secrets here, use Credentials instead."
        >
          {/* min-h keeps the box usable on short viewports; the sheet body
              scrolls as the fallback below that. */}
          <Textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="min-h-[160px] flex-1"
            placeholder={"# Deploy to staging\n\n1. Run the test suite\n2. ..."}
            error={contentTooLarge}
          />
          <p
            className={`mt-2 shrink-0 text-right text-xs ${
              contentTooLarge ? "text-danger" : "text-text-dim"
            }`}
          >
            {contentChars.toLocaleString()} / {MAX_CONTENT_CHARS.toLocaleString()} characters
          </p>
        </FormField>
      </div>
    </Sheet>
  );
}
