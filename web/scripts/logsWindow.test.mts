// Regression tests for the bounded view-window policy (LogsView fix).
// Run with: node --experimental-strip-types web/scripts/logsWindow.test.mts
import assert from "node:assert";
import { applyHistoryPage, applyLiveBatch, type ViewWindowPolicy } from "../src/lib/logsWindow.ts";

type Row = { id: number };
const mk = (n: number, start: number): Row[] => Array.from({ length: n }, (_, i) => ({ id: start - i }));
const policy: ViewWindowPolicy = { tailRows: 5, historyRows: 3 };

// 1. Live batch under budget: nothing evicted.
{
  const prev = mk(3, 100); // ids 100,99,98
  const r = applyLiveBatch(prev, mk(2, 102), policy, 0);
  assert.deepStrictEqual(r.rows.map((x) => x.id), [102, 101, 100, 99, 98]);
  assert.strictEqual(r.historyCount, 0);
}

// 2. Live batch over tail budget with no history: oldest tail evicted.
{
  const prev = mk(4, 100);
  const r = applyLiveBatch(prev, mk(3, 103), policy, 0);
  assert.strictEqual(r.rows.length, 5);
  assert.deepStrictEqual(r.rows.map((x) => x.id), [103, 102, 101, 100, 99]);
}

// 3. History suffix is protected from live eviction.
{
  const prev = [...mk(3, 100), ...mk(2, 97)]; // tail 100..98, history 97,96
  const r = applyLiveBatch(prev, mk(2, 102), policy, 2);
  // budget 5+2=7, merged 7 -> no eviction
  assert.deepStrictEqual(r.rows.map((x) => x.id), [102, 101, 100, 99, 98, 97, 96]);
  assert.strictEqual(r.historyCount, 2);
}
{
  const prev = [...mk(4, 100), ...mk(3, 96)]; // tail 100..97, history 96..94
  const r = applyLiveBatch(prev, mk(3, 103), policy, 3);
  // merged 10 > budget 8: evict 2 tail rows (98,97), history intact
  assert.deepStrictEqual(r.rows.map((x) => x.id), [103, 102, 101, 100, 99, 96, 95, 94]);
  assert.strictEqual(r.historyCount, 3);
}

// 4. History page appends and trims only within its own budget.
{
  const prev = [...mk(3, 100), ...mk(2, 97)];
  const r = applyHistoryPage(prev, mk(3, 95), policy, 2);
  // history 2+3=5 > 3: keep the 3 newest history rows (97,96,95), tail untouched
  assert.deepStrictEqual(r.rows.map((x) => x.id), [100, 99, 98, 97, 96, 95]);
  assert.strictEqual(r.historyCount, 3);
}

// 5. History page under budget: pure append.
{
  const prev = [...mk(2, 100), ...mk(1, 98)];
  const r = applyHistoryPage(prev, mk(1, 97), policy, 1);
  assert.deepStrictEqual(r.rows.map((x) => x.id), [100, 99, 98, 97]);
  assert.strictEqual(r.historyCount, 2);
}

// 6. Edge: empty fresh batch and empty prev.
{
  assert.deepStrictEqual(applyLiveBatch([], [], policy, 0).rows, []);
  const r = applyLiveBatch(mk(2, 10), [], policy, 0);
  assert.strictEqual(r.rows.length, 2);
}

// 7. Edge: single batch larger than the whole budget.
{
  const r = applyLiveBatch([], mk(20, 100), { tailRows: 5, historyRows: 3 }, 0);
  assert.strictEqual(r.rows.length, 5);
  assert.deepStrictEqual(r.rows.map((x) => x.id), [100, 99, 98, 97, 96]);
}

// 8. Invariant sweep: bounded total, tail/history id-disjointness, newest-first.
//    History ids live in a disjoint older id-space so segments never collide.
{
  let rows: Row[] = [];
  let historyCount = 0;
  let nextId = 1000;
  let nextHistoryId = 900; // disjoint older id-space, strictly below the tail
  for (let step = 0; step < 500; step++) {
    const n = step % 7 === 0 ? 4 : 1;
    const batch = mk(n, nextId + n - 1); // strictly newer than anything in prev
    nextId += n;
    ({ rows, historyCount } = applyLiveBatch(rows, batch, policy, historyCount));
    if (step % 23 === 0) {
      nextHistoryId -= 3;
      const page = mk(3, nextHistoryId + 2);
      ({ rows, historyCount } = applyHistoryPage(rows, page, policy, historyCount));
    }
    assert.ok(rows.length <= policy.tailRows + policy.historyRows, `unbounded at step ${step}`);
    assert.ok(historyCount <= policy.historyRows, `history over budget at step ${step}`);
    for (let i = 1; i < rows.length; i++) {
      assert.ok(rows[i - 1].id > rows[i].id, `order broken at step ${step}`);
    }
    if (historyCount > 0) {
      const tail = rows.slice(0, rows.length - historyCount);
      const hist = rows.slice(rows.length - historyCount);
      assert.ok(tail.every((t) => t.id > hist[0].id), `segment overlap at step ${step}`);
      assert.ok(tail.length <= policy.tailRows, `tail over budget at step ${step}`);
    }
  }
}

console.log("logsWindow: all assertions passed");
