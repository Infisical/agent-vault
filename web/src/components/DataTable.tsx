import type { ReactNode } from "react";

export interface Column<T> {
  key: string;
  header: string;
  render: (item: T, index: number) => ReactNode;
  align?: "left" | "right";
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  rowKey: (item: T, index: number) => string | number;
  onRowClick?: (item: T, index: number) => void;
  emptyTitle?: string;
  emptyDescription?: ReactNode;
}

// Keeps the identifying column visible while the rest of a wide table
// scrolls horizontally on small screens. No effect from md up.
const STICKY_FIRST_COL = "max-md:sticky max-md:left-0 max-md:z-[1] max-md:bg-surface";

export default function DataTable<T>({
  columns,
  data,
  rowKey,
  onRowClick,
  emptyTitle = "No data",
  emptyDescription,
}: DataTableProps<T>) {
  return (
    <div className="border border-border rounded-xl overflow-hidden bg-surface">
      {/* Below md the table scrolls sideways inside its card instead of
          pushing the page wider, with the first column pinned. */}
      <div className="overflow-x-auto overscroll-x-contain">
      <table className="w-full min-w-max md:min-w-0">
        <thead>
          <tr className="border-b border-border">
            {columns.map((col, colIndex) => (
              <th
                key={col.key}
                className={`${colIndex === 0 ? STICKY_FIRST_COL + " " : ""}px-5 py-3 text-xs font-semibold text-text-muted uppercase tracking-wider ${col.align === "right" ? "text-right w-0" : "text-left"}${col.className ? " " + col.className : ""}`}
              >
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.length === 0 ? (
            <tr>
              <td colSpan={columns.length} className="text-center py-16">
                <div className="max-w-[360px] mx-auto">
                  <div className="text-base font-semibold text-text-muted mb-1">
                    {emptyTitle}
                  </div>
                  {emptyDescription && (
                    <div className="text-sm text-text-muted">
                      {emptyDescription}
                    </div>
                  )}
                </div>
              </td>
            </tr>
          ) : (
            data.map((item, index) => (
              <tr
                key={rowKey(item, index)}
                className={`border-b border-border last:border-b-0 hover:bg-bg/50 transition-colors${onRowClick ? " cursor-pointer" : ""}`}
                onClick={onRowClick ? () => onRowClick(item, index) : undefined}
              >
                {columns.map((col, colIndex) => (
                  <td key={col.key} className={`${colIndex === 0 ? STICKY_FIRST_COL + " " : ""}px-5 py-3.5${col.align === "right" ? " w-0" : ""}${col.className ? " " + col.className : ""}`}>
                    {col.align === "right" ? (
                      <div className="flex justify-end">{col.render(item, index)}</div>
                    ) : (
                      col.render(item, index)
                    )}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
      </div>
    </div>
  );
}
