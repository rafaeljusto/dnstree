import { test } from "node:test";
import assert from "node:assert/strict";

import {
  KINDS, kindOf, cookieOf, trustOf, took, plural, flagsOf, flatten, asked, aside, resultOf, verdictOf,
  chainState, haystack, chipsOf, timeline, ticks,
} from "../assets/walk.js";
import * as scene from "../assets/scene/walk.js";
import { golden, zone, step } from "./fixtures.mjs";

test("the page and the scene call a hop the same things", () => {
  assert.deepEqual(Object.keys(KINDS), Object.keys(scene.KINDS));
  for (const [name, kind] of Object.entries(KINDS)) {
    assert.equal(kind.tone, scene.KINDS[name].tone, name);
    assert.equal(kind.says, scene.KINDS[name].says, name);
  }
  for (const ms of [undefined, 0.3, 9.4, 41.5, 2000]) assert.equal(took(ms), scene.took(ms));
});

test("the page and the scene come to the same verdict", () => {
  const walks = {
    "the golden walk": golden().root,
    "a bogus cut": zone(step("referral", { dnssec: { state: "bogus" } }, step("answer"))),
    "a filtered answer": zone(step("filtered")),
    "a walk that got nowhere": zone(step("timeout")),
    "an answer only inside an aside": zone(step("referral", { aside: true }, step("answer"))),
    "a minimised NODATA": zone(step("nodata", { minimised: true })),
  };
  for (const [name, root] of Object.entries(walks)) {
    const flat = flatten(root);
    const drawn = scene.flatten(root);
    assert.deepEqual(verdictOf(flat), scene.verdictOf(drawn, scene.resultOf(drawn[0])), name);
    assert.equal(resultOf(root), scene.resultOf(drawn[0])?.step ?? null, name);
  }
});

test("what this build does not know is shown as itself", () => {
  assert.deepEqual(kindOf("new"), { icon: "unknown", tone: "quiet", says: "new" });
  assert.deepEqual(cookieOf("new"), { text: "cookie new", tone: "quiet", says: "new" });
  assert.deepEqual(trustOf("new"), trustOf("indeterminate"));
});

test("a count names its unit, and only the flags that are set are shown", () => {
  assert.equal(plural(1, "query", "queries"), "1 query");
  assert.equal(plural(0, "query", "queries"), "0 queries");
  assert.deepEqual(flagsOf({ aa: true, tc: false, do: true }), ["AA", "DO"]);
  assert.deepEqual(flagsOf(undefined), []);
});

test("a hop is an aside when anything above it is", () => {
  const hops = flatten(zone(step("referral", { aside: true }, step("referral", {}, step("answer"))), step("answer")));
  assert.deepEqual(hops.map(aside), [false, true, true, true, false]);
  assert.deepEqual(hops.map((hop) => asked(hop.step)), [false, true, true, true, true]);
});

test("a note that the budget ran out is no query", () => {
  const hops = flatten(zone(step("referral", {}, { zone: "example.", kind: "error", error: "gave up after 2 queries" })));
  assert.deepEqual(hops.map((hop) => asked(hop.step)), [false, true, false]);
});

test("the chain is as good as its worst cut, and unknown without one", () => {
  assert.equal(chainState(flatten(golden().root)), "insecure");
  assert.equal(chainState(flatten(zone(step("answer")))), "indeterminate");
});

test("a hop is found by what the trace says of it", () => {
  const hops = flatten(golden().root);
  const found = (query) => hops.filter((hop) => haystack(hop.step).includes(query)).map((hop) => hop.id);
  assert.deepEqual(found("as10745"), [4]);
  assert.deepEqual(found("93.184.216.34"), [4]);
  assert.deepEqual(found("i/o timeout"), [2]);
  assert.deepEqual(found("fra2"), [1]);
  assert.deepEqual(found("dnskey"), [5]);
  assert.deepEqual(found("cookie"), [1], "a cookie is found by the word shown for it");
  assert.equal(haystack(hops[4].step), haystack(hops[4].step).toLowerCase());
});

test("the chips a hop wears", () => {
  const hops = flatten(golden().root);
  const texts = (hop) => chipsOf(hop.step).map((chip) => chip.text);
  assert.deepEqual(texts(hops[1]), ["→ com.", "12 ms", "@fra2", "cookie", "insecure"]);
  assert.deepEqual(texts(hops[2]), ["timeout", "2.00 s"]);
  assert.deepEqual(texts(hops[4]), ["9.4 ms", "1187 of 1232 bytes", "AS10745", "AA DO", "secure"]);
  assert.deepEqual(texts(hops[5]), ["8.0 ms", "AA", "aside", "DNSKEY of example.com."]);

  const trust = chipsOf(hops[4].step).find((chip) => chip.icon);
  assert.deepEqual(trust, { text: "secure", tone: "ok", title: "the chain of trust at this cut", icon: "secure" });
  assert.equal(chipsOf(hops[1].step).at(-1).title, "the parent published no DS");
});

test("a chip is coloured by what is wrong", () => {
  const tone = (fields, text) => chipsOf(step("answer", fields)).find((chip) => chip.text === text)?.tone;
  const cases = {
    "a failing rcode": [{ rcode: "REFUSED" }, "REFUSED", "warn"],
    "a slow server": [{ rtt_ms: 900 }, "900 ms", "warn"],
    "a quick one": [{ rtt_ms: 12 }, "12 ms", "quiet"],
    "a cookie not ours": [{ cookie: "mismatch" }, "cookie not ours", "bad"],
    "a withheld extended error": [{ extended: [{ code: 15, withheld: true }] }, "ede", "warn"],
    "a bogus cut": [{ dnssec: { state: "bogus" } }, "bogus", "bad"],
  };
  for (const [name, [fields, text, want]] of Object.entries(cases)) assert.equal(tone(fields, text), want, name);
  assert.ok(!chipsOf(step("answer", { rcode: "NOERROR" })).some((chip) => chip.text === "NOERROR"));
  assert.ok(!chipsOf(step("answer", { flags: { edns: true } })).some((chip) => chip.text === "EDNS"), "EDNS is not news");
});

/* ── the timeline ──────────────────────────────────────────────────────── */

test("the timeline has every query in the order it went out", () => {
  const hops = flatten(zone(
    step("referral", { asked: {}, start_ms: 0, rtt_ms: 20 },
      step("timeout", { asked: {}, start_ms: 30, rtt_ms: 400 }),
      step("answer", { asked: {}, start_ms: 21, rtt_ms: 5 })),
  ));
  const { spans, total } = timeline(hops, 300);
  assert.deepEqual(spans.map((span) => span.start), [0, 21, 30]);
  assert.equal(total, 430, "the walk ran past what it said it took");
  assert.equal(timeline(hops, 1000).total, 1000);
});

test("a walk that gave up stands where the last thing before it finished", () => {
  const hops = flatten(zone(
    step("referral", { asked: {}, start_ms: 0, rtt_ms: 50 }, step("error", { error: "no address", asked: undefined })),
  ));
  const { spans } = timeline(hops, 0);
  assert.deepEqual(spans.map(({ start, rtt, stop }) => ({ start, rtt, stop })), [
    { start: 0, rtt: 50, stop: undefined },
    { start: 50, rtt: 0, stop: true },
  ]);
});

test("a timeline with nothing on it still has a length to divide by", () => {
  assert.equal(timeline(flatten(zone()), undefined).total, 0.001);
});

test("the ticks are round and few", () => {
  const cases = {
    "a quick walk": [42, [0, 10, 20, 30, 40]],
    "a second and a bit": [1300, [0, 500, 1000]],
    "exactly a round number": [100, [0, 50, 100]],
    "a walk that took no time": [0.001, [0, 0.001]],
    "a time no walk takes": [Infinity, [0]],
  };
  for (const [name, [total, want]] of Object.entries(cases)) assert.deepEqual(ticks(total), want, name);
  for (let total = 0.01; total < 1e6; total *= 3.7) {
    const marks = ticks(total);
    assert.ok(marks.length >= 2 && marks.length <= 6, `${marks.length} ticks for ${total}`);
    assert.ok(marks.at(-1) <= total + 1e-9);
  }
});
