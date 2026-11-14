import type { ReactNode } from "react";
import Tooltip from "./Tooltip";

/** A "?" chip that reveals its content on hover/focus. */
export default function InfoTooltip({ children }: { children: ReactNode }) {
  return (
    <Tooltip
      className="inline-flex"
      trigger={
        <span
          tabIndex={0}
          aria-label="More info"
          className="inline-flex items-center justify-center w-3.5 h-3.5 rounded-full border border-text-dim text-text-dim cursor-help normal-case font-normal text-[10px] leading-none focus:outline-none focus:border-text-muted focus:text-text-muted hover:border-text-muted hover:text-text-muted"
        >
          ?
        </span>
      }
    >
      {children}
    </Tooltip>
  );
}
