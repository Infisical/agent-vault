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
      <table className="w-full">
        <thead>
          <tr className="border-b border-border">
            {columns.map((col) => (
              <th
                key={col.key}
                className={`px-5 py-3 text-xs font-semibold text-text-muted uppercase tracking-wider ${col.align === "right" ? "text-right w-0" : "text-left"}${col.className ? " " + col.className : ""}`}
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
                {columns.map((col) => (
                  <td key={col.key} className={`px-5 py-3.5${col.align === "right" ? " w-0" : ""}${col.className ? " " + col.className : ""}`}>
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
  );
}
