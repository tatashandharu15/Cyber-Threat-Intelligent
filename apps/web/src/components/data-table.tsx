"use client";

import {
  flexRender,
  getCoreRowModel,
  useReactTable,
  type ColumnDef,
} from "@tanstack/react-table";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { DataTableSkeleton, EmptyState, ErrorState } from "@/components/states";

export interface DataTableProps<T> {
  columns: ColumnDef<T, unknown>[];
  rows: T[];
  isLoading?: boolean;
  isError?: boolean;
  onRetry?: () => void;
  emptyMessage?: string;
}

export function DataTable<T>({
  columns,
  rows,
  isLoading = false,
  isError = false,
  onRetry,
  emptyMessage = "No records found.",
}: DataTableProps<T>) {
  const table = useReactTable({
    data: rows,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  if (isError) {
    return <ErrorState onRetry={onRetry} />;
  }

  return (
    <div className="rounded-lg border">
      <Table>
        <THead>
          {table.getHeaderGroups().map((headerGroup) => (
            <TR key={headerGroup.id}>
              {headerGroup.headers.map((header) => (
                <TH key={header.id}>
                  {header.isPlaceholder
                    ? null
                    : flexRender(
                        header.column.columnDef.header,
                        header.getContext(),
                      )}
                </TH>
              ))}
            </TR>
          ))}
        </THead>
        {isLoading ? (
          <DataTableSkeleton columns={columns.length} />
        ) : rows.length === 0 ? (
          <TBody>
            <TR>
              <TD colSpan={columns.length} className="p-0">
                <EmptyState message={emptyMessage} />
              </TD>
            </TR>
          </TBody>
        ) : (
          <TBody>
            {table.getRowModel().rows.map((row) => (
              <TR key={row.id}>
                {row.getVisibleCells().map((cell) => (
                  <TD key={cell.id}>
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TD>
                ))}
              </TR>
            ))}
          </TBody>
        )}
      </Table>
    </div>
  );
}
