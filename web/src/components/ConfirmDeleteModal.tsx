import { useState } from "react";
import Modal from "./Modal";
import Button from "./Button";
import Input from "./Input";
import FormField from "./FormField";
import { ErrorBanner } from "./shared";

interface ConfirmDeleteModalProps {
  open: boolean;
  onClose: () => void;
  onConfirm: () => Promise<void>;
  title: string;
  description: string;
  confirmLabel: string;
  confirmValue: string;
  inputLabel?: string;
}

export default function ConfirmDeleteModal({
  open,
  onClose,
  onConfirm,
  title,
  description,
  confirmLabel,
  confirmValue,
  inputLabel = "Type to confirm",
}: ConfirmDeleteModalProps) {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  function handleClose() {
    setInput("");
    setError("");
    onClose();
  }

  async function handleConfirm() {
    setLoading(true);
    setError("");
    try {
      await onConfirm();
      setInput("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title={title}
      description={description}
      footer={
        <>
          <Button variant="secondary" onClick={handleClose}>
            Cancel
          </Button>
          <Button
            onClick={handleConfirm}
            disabled={input !== confirmValue}
            loading={loading}
            className="!bg-danger !text-white hover:!bg-danger/90"
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      <FormField label={inputLabel}>
        <Input
          value={input}
          onChange={(e) => {
            setInput(e.target.value);
            setError("");
          }}
          placeholder={confirmValue}
        />
      </FormField>
      {error && <ErrorBanner message={error} className="mt-3" />}
    </Modal>
  );
}
