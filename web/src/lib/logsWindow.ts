/**
 * Bounded view-window policy for log-style tables that tail a live feed.
 *
 * The view holds the newest `tailRows` rows of the live feed plus up to
 * `historyRows` rows the user explicitly loaded with "Load more". Live
 * traffic may evict tail rows but never evicts loaded history; loading
 * even older history evicts the oldest loaded rows beyond the budget.
 * Total state is therefore bounded by `tailRows + historyRows` no matter
 * how much traffic flows through.
 *
 * Rows are ordered newest-first. Loaded history is a contiguous suffix
 * whose ids are strictly older than every tail row (the tail only gains
 * newer rows), so the two segments never overlap and never need
 * deduplication.
 */
export interface ViewWindowPolicy {
  /** Newest rows kept while live polling appends; older tail rows fall off. */
  tailRows: number;
  /** Rows explicitly loaded via "Load more" that live traffic will not evict. */
  historyRows: number;
}

export interface WindowResult<T> {
  rows: T[];
  /** Number of rows in the trailing loaded-history segment. */
  historyCount: number;
}

/**
 * Merge a batch of newly observed rows (newest-first, ids strictly greater
 * than every row in `prev`) at the head, evicting the oldest tail rows when
 * the live tail would exceed `tailRows`. The loaded-history suffix is never
 * touched: the eviction budget always leaves room for it.
 */
export function applyLiveBatch<T extends { id: number }>(
  prev: T[],
  fresh: T[],
  policy: ViewWindowPolicy,
  historyCount: number,
): WindowResult<T> {
  const merged = [...fresh, ...prev];
  const budget = policy.tailRows + historyCount;
  if (merged.length <= budget) {
    return { rows: merged, historyCount };
  }
  // Only tail rows are evictable, and there are always enough of them to
  // absorb the excess: excess = merged.length - tailRows - historyCount
  // and evictable = merged.length - historyCount, so excess <= evictable.
  // (historyCount must equal the length of prev's history suffix.)
  const tailStart = policy.tailRows;
  const tail = merged.slice(0, tailStart);
  const history = historyCount > 0 ? merged.slice(merged.length - historyCount) : [];
  return { rows: [...tail, ...history], historyCount };
}

/**
 * Append a page of older rows (ids strictly less than every row in `prev`)
 * loaded via "Load more", trimming the oldest loaded rows beyond
 * `historyRows`. Because the previous historyCount never exceeds the
 * budget, the trim only reaches into the freshly appended page and never
 * into the tail.
 */
export function applyHistoryPage<T extends { id: number }>(
  prev: T[],
  older: T[],
  policy: ViewWindowPolicy,
  historyCount: number,
): WindowResult<T> {
  const merged = [...prev, ...older];
  const nextHistoryCount = historyCount + older.length;
  if (nextHistoryCount > policy.historyRows) {
    const excess = nextHistoryCount - policy.historyRows;
    return { rows: merged.slice(0, merged.length - excess), historyCount: policy.historyRows };
  }
  return { rows: merged, historyCount: nextHistoryCount };
}
