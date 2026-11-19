import {
  type ColumnDef,
  type SortingState,
  flexRender,
  getCoreRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";
import { type ReactNode, useEffect, useState } from "react";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { type Route, setParams } from "@/router";

declare module "@tanstack/react-table" {
  interface ColumnMeta<TData, TValue> {
    align?: "right";
    className?: string;
  }
}

export const PAGE_SIZES = [10, 25, 50, 100];

/** Server-side paging and sorting state, kept in the URL (page, size, sort, order). */
export interface ServerState {
  page: number; // 0-based
  size: number;
  sort: string;
  desc: boolean;
}

export function serverState(route: Route, defaults: { sort: string; desc?: boolean; size?: number }): ServerState {
  const p = route.params;
  const size = Number(p.get("size")) || defaults.size || 25;
  return {
    page: Math.max(0, (Number(p.get("page")) || 1) - 1),
    size: PAGE_SIZES.includes(size) ? size : 25,
    sort: p.get("sort") ?? defaults.sort,
    desc: p.has("order") ? p.get("order") !== "asc" : (defaults.desc ?? true),
  };
}

/** API query parameters for a server state. */
export const serverQuery = (s: ServerState) => ({ limit: s.size, offset: s.page * s.size, sort: s.sort, order: s.desc ? "desc" : "asc" });

interface DataTableProps<T> {
  columns: ColumnDef<T, any>[];
  data: T[];
  getRowId: (row: T) => string;
  onRowClick?: (row: T) => void;
  /** Client mode: initial sort. */
  initialSort?: SortingState;
  /** Server mode: the rows are one page; sorting and paging go through the URL. */
  server?: { state: ServerState; total: number };
  pageSize?: number;
  empty?: ReactNode;
  paginate?: boolean;
  className?: string;
}

/** Sortable, paginated table, client-side or server-side. */
export function DataTable<T>({
  columns,
  data,
  getRowId,
  onRowClick,
  initialSort = [],
  server,
  pageSize = 25,
  empty = "No results.",
  paginate = true,
  className,
}: DataTableProps<T>) {
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize });

  const sortState: SortingState = server ? (server.state.sort ? [{ id: server.state.sort, desc: server.state.desc }] : []) : sorting;
  const pageState = server ? { pageIndex: server.state.page, pageSize: server.state.size } : pagination;

  const table = useReactTable({
    data,
    columns,
    getRowId,
    state: { sorting: sortState, pagination: pageState },
    manualSorting: !!server,
    manualPagination: !!server,
    rowCount: server?.total,
    sortDescFirst: true,
    onSortingChange: (updater) => {
      const next = typeof updater === "function" ? updater(sortState) : updater;
      if (!server) return setSorting(next);
      const s = next[0];
      setParams({ sort: s?.id, order: s ? (s.desc ? "desc" : "asc") : undefined, page: undefined });
    },
    onPaginationChange: (updater) => {
      const next = typeof updater === "function" ? updater(pageState) : updater;
      if (!server) return setPagination(next);
      setParams({ page: next.pageIndex > 0 ? String(next.pageIndex + 1) : undefined, size: next.pageSize !== 25 ? String(next.pageSize) : undefined });
    },
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: server ? undefined : getSortedRowModel(),
    getPaginationRowModel: server || !paginate ? undefined : getPaginationRowModel(),
    // Data refreshes every 30s; keep the user's page instead of jumping to the first one.
    autoResetPageIndex: false,
  });

  const total = server ? server.total : data.length;
  const pageCount = Math.max(1, Math.ceil(total / pageState.pageSize));
  useEffect(() => {
    if (pageState.pageIndex > 0 && pageState.pageIndex >= pageCount) table.setPageIndex(pageCount - 1);
  }, [pageCount, pageState.pageIndex, table]);

  const rows = table.getRowModel().rows;
  const from = total ? pageState.pageIndex * pageState.pageSize + 1 : 0;
  const to = Math.min(total, (pageState.pageIndex + 1) * pageState.pageSize);
  const canPrev = pageState.pageIndex > 0;
  const canNext = pageState.pageIndex < pageCount - 1;

  return (
    <div className={cn("overflow-hidden rounded-lg border bg-card", className)}>
      <Table>
        <TableHeader>
          {table.getHeaderGroups().map((hg) => (
            <TableRow key={hg.id} className="hover:bg-transparent">
              {hg.headers.map((h) => {
                const meta = h.column.columnDef.meta;
                const sorted = h.column.getIsSorted();
                return (
                  <TableHead
                    key={h.id}
                    className={cn("h-9 text-xs text-muted-foreground", meta?.align === "right" && "text-right", meta?.className)}
                    aria-sort={sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : undefined}
                  >
                    {h.isPlaceholder ? null : h.column.getCanSort() ? (
                      <button
                        type="button"
                        onClick={h.column.getToggleSortingHandler()}
                        className={cn(
                          "-mx-1 inline-flex cursor-pointer items-center gap-1 rounded px-1 py-0.5 font-medium hover:text-foreground",
                          meta?.align === "right" && "flex-row-reverse",
                          sorted && "text-foreground",
                        )}
                      >
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {sorted === "asc" ? (
                          <ArrowUp className="size-3.5" />
                        ) : sorted === "desc" ? (
                          <ArrowDown className="size-3.5" />
                        ) : (
                          <ArrowUpDown className="size-3.5 opacity-40" />
                        )}
                      </button>
                    ) : (
                      flexRender(h.column.columnDef.header, h.getContext())
                    )}
                  </TableHead>
                );
              })}
            </TableRow>
          ))}
        </TableHeader>
        <TableBody>
          {rows.length ? (
            rows.map((row) => (
              <TableRow
                key={row.id}
                onClick={
                  onRowClick
                    ? (e) => {
                        // Let links and buttons inside the row do their own thing.
                        if ((e.target as HTMLElement).closest("a,button")) return;
                        onRowClick(row.original);
                      }
                    : undefined
                }
                className={cn(onRowClick && "cursor-pointer")}
              >
                {row.getVisibleCells().map((cell) => {
                  const meta = cell.column.columnDef.meta;
                  return (
                    <TableCell
                      key={cell.id}
                      className={cn("py-2 align-top whitespace-normal", meta?.align === "right" && "text-right tabular-nums", meta?.className)}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </TableCell>
                  );
                })}
              </TableRow>
            ))
          ) : (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={columns.length} className="h-24 text-center text-muted-foreground">
                {empty}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>

      {paginate && total > 10 && (
        <div className="flex flex-wrap items-center justify-between gap-3 border-t px-3 py-2 text-xs text-muted-foreground">
          <span className="tabular-nums">
            {from}–{to} of {total}
          </span>
          <div className="flex items-center gap-2">
            <span className="hidden sm:inline">Rows</span>
            <Select value={String(pageState.pageSize)} onValueChange={(v) => table.setPagination({ pageIndex: 0, pageSize: Number(v) })}>
              <SelectTrigger size="sm" className="h-7 w-[70px]" aria-label="Rows per page">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {PAGE_SIZES.map((n) => (
                  <SelectItem key={n} value={String(n)}>
                    {n}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button variant="ghost" size="icon-sm" onClick={() => table.setPageIndex(0)} disabled={!canPrev} aria-label="First page">
              <ChevronsLeft />
            </Button>
            <Button variant="ghost" size="icon-sm" onClick={() => table.setPageIndex(pageState.pageIndex - 1)} disabled={!canPrev} aria-label="Previous page">
              <ChevronLeft />
            </Button>
            <span className="tabular-nums">
              {pageState.pageIndex + 1} / {pageCount}
            </span>
            <Button variant="ghost" size="icon-sm" onClick={() => table.setPageIndex(pageState.pageIndex + 1)} disabled={!canNext} aria-label="Next page">
              <ChevronRight />
            </Button>
            <Button variant="ghost" size="icon-sm" onClick={() => table.setPageIndex(pageCount - 1)} disabled={!canNext} aria-label="Last page">
              <ChevronsRight />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
