import { test } from "node:test";
import assert from "node:assert/strict";

import {
  KINDS, TONES, kindOf, took, flatten, asked, resultOf, verdictOf, chainState, widthOf,
  layout, drift, schedule, titleOf, subtitleOf, factsOf, declutter, stepFrom,
} from "../assets/scene/walk.js";
import { golden, zone, step, chain } from "./fixtures.mjs";

const walked = (root) => {
  const hops = flatten(root);
  return { hops, result: resultOf(hops[0]) };
};

test("every kind is drawn with a shape and a tone the scene has", () => {
  for (const [name, kind] of Object.entries(KINDS)) {
    assert.ok(["ico", "octa", "sphere", "torus", "cube", "tetra"].includes(kind.shape), name);
    assert.ok(TONES[kind.tone], name);
  }
  assert.deepEqual(kindOf("something new"), { shape: "tetra", size: 0.5, tone: "quiet", says: "something new" });
});

test("a duration reads in the unit it was made in", () => {
  const cases = {
    "nothing is said of a time that was not kept": [undefined, ""],
    "under a millisecond keeps two decimals": [0.25, "0.25 ms"],
    "a few milliseconds keep one": [9.4, "9.4 ms"],
    "tens of milliseconds are whole": [41.5, "42 ms"],
    "a second or more is in seconds": [2000, "2.00 s"],
  };
  for (const [name, [ms, want]] of Object.entries(cases)) assert.equal(took(ms), want, name);
});

test("the walk is flattened in the order it was made", () => {
  const { hops } = walked(golden().root);
  assert.deepEqual(hops.map((hop) => hop.step.kind), ["zone", "referral", "timeout", "referral", "answer", "answer", "skipped"]);
  assert.deepEqual(hops.map((hop) => hop.depth), [0, 1, 2, 2, 3, 4, 3]);
  assert.deepEqual(hops.map((hop) => hop.id), [0, 1, 2, 3, 4, 5, 6]);
  for (const hop of hops.slice(1)) assert.ok(hop.parent.kids.includes(hop));
  assert.deepEqual(hops.filter((hop) => asked(hop.step)).map((hop) => hop.id), [1, 2, 3, 4, 5]);
});

test("the result is the deepest hop that is neither an aside nor minimised", () => {
  const cases = {
    "the answer, not the DNSKEY asked beside it": [golden().root, (hops) => hops[4]],
    "nothing, when no hop answered": [zone(step("referral", {}, step("timeout"))), () => null],
    "not a minimised NODATA on the way down": [
      zone(step("nodata", { minimised: true }, step("referral", {}, step("timeout")))), () => null,
    ],
    "the alias, when its chase ended nowhere": [zone(step("cname", {}, step("timeout"))), (hops) => hops[1]],
    "not an answer inside an aside": [zone(step("referral", { aside: true }, step("answer"))), () => null],
  };
  for (const [name, [root, want]] of Object.entries(cases)) {
    const { hops, result } = walked(root);
    assert.equal(result, want(hops), name);
  }
});

test("the verdict says the worst of what the walk came to", () => {
  const cases = {
    "an answer is answered": [golden().root, "answered"],
    "a bogus cut outweighs the answer": [zone(step("referral", { dnssec: { state: "bogus" } }, step("answer"))), "bogus"],
    "a filtered answer is not no answer": [zone(step("filtered")), "filtered"],
    "a filtered hop beside an answer is still an answer": [zone(step("filtered"), step("answer")), "answered"],
    "a walk that got nowhere": [zone(step("timeout")), "no answer"],
  };
  for (const [name, [root, want]] of Object.entries(cases)) {
    const { hops, result } = walked(root);
    assert.equal(verdictOf(hops, result).text, want, name);
  }
});

test("the chain is as good as its worst cut", () => {
  const cuts = (...states) => flatten(zone(...states.map((state) => step("referral", { dnssec: { state } }))));
  assert.equal(chainState(flatten(golden().root)), "insecure");
  assert.equal(chainState(cuts("secure", "indeterminate", "insecure")), "indeterminate");
  assert.equal(chainState(cuts("secure", "bogus")), "bogus");
  assert.equal(chainState(cuts("secure")), "secure");
  assert.equal(chainState(flatten(zone(step("answer")))), undefined);
});

/* ── layout ────────────────────────────────────────────────────────────── */

const finite = (v) => v.every(Number.isFinite);

test("every hop is placed somewhere real", () => {
  for (const root of [golden().root, zone(), chain(1), chain(12)]) {
    const { hops } = walked(root);
    const bounds = layout(hops);
    for (const hop of hops) assert.ok(finite(hop.pos), `hop ${hop.id} at ${hop.pos}`);
    assert.ok(finite([bounds.radius, bounds.spread, bounds.height, bounds.floor, ...bounds.centre]));
  }
});

test("each zone cut is a level lower, and the cone is centred on its height", () => {
  const { hops } = walked(chain(6));
  const bounds = layout(hops);
  for (const hop of hops.slice(1)) assert.ok(hop.pos[1] < hop.parent.pos[1], `hop ${hop.id}`);
  const ys = hops.map((hop) => hop.pos[1]);
  assert.ok(Math.abs(Math.max(...ys) + Math.min(...ys)) < 1e-9);
  assert.ok(Math.abs(bounds.height - (Math.max(...ys) - Math.min(...ys))) < 1e-9);
  assert.ok(bounds.floor < Math.min(...ys), "the floor is under the lowest hop");
  assert.deepEqual([hops[0].pos[0], hops[0].pos[2]], [0, 0], "the root is on the axis");
});

// Every hop on a ring is given at least the arc it needs, so no two can land
// on each other however crowded the ring is.
const crowding = (hops) => {
  let worst = Infinity;
  for (const a of hops) {
    for (const b of hops) {
      if (a.id >= b.id || a.depth !== b.depth || !a.depth) continue;
      const apart = Math.hypot(a.pos[0] - b.pos[0], a.pos[2] - b.pos[2]);
      worst = Math.min(worst, apart / ((widthOf(a.step) + widthOf(b.step)) / 2));
    }
  }
  return worst;
};

test("hops on the same ring keep apart however many there are", () => {
  const cases = {
    "a few referrals": zone(step("referral"), step("referral"), step("referral")),
    "sixty servers asked at once": zone(...Array.from({ length: 60 }, () => step("timeout"))),
    "a signed fan, which is wider": zone(...Array.from({ length: 40 }, () => step("referral", { dnssec: { state: "secure" } }))),
    "a deep subtree beside shallow siblings": zone(
      step("referral", {}, ...Array.from({ length: 30 }, () => step("answer"))),
      step("timeout"), step("timeout"),
    ),
  };
  for (const [name, root] of Object.entries(cases)) {
    const { hops } = walked(root);
    layout(hops);
    // A chord is shorter than the arc it spans, by under 5% for what a hop needs.
    assert.ok(crowding(hops) > 0.95, `${name}: ${crowding(hops)}`);
  }
});

test("a crowded walk grows its rings, and its levels by less", () => {
  const few = walked(zone(step("referral", {}, step("answer"))));
  const many = walked(zone(...Array.from({ length: 80 }, () => step("referral", {}, step("answer")))));
  const a = layout(few.hops);
  const b = layout(many.hops);
  assert.ok(b.radius > a.radius * 2);
  assert.ok(b.height > a.height);
  assert.ok(b.height / a.height < b.radius / a.radius, "still a cone, not a plate");
});

test("the camera is aimed at where the hops went", () => {
  // Everything down one side of the ring: the centre moves off the axis.
  const { hops } = walked(zone(step("referral", {}, step("answer"), step("answer"), step("answer"))));
  const bounds = layout(hops);
  const xs = hops.map((hop) => hop.pos[0]);
  const zs = hops.map((hop) => hop.pos[2]);
  assert.ok(Math.abs(bounds.centre[0] - (Math.min(...xs) + Math.max(...xs)) / 2) < 1e-9);
  assert.ok(Math.abs(bounds.centre[2] - (Math.min(...zs) + Math.max(...zs)) / 2) < 1e-9);
  for (const hop of hops) {
    assert.ok(Math.hypot(hop.pos[0] - bounds.centre[0], hop.pos[2] - bounds.centre[2]) <= bounds.spread + 1e-9);
  }
});

test("a hop floats near its place, and stands still without motion", () => {
  const pos = [1, 2, 3];
  assert.deepEqual(drift(pos, 0.7, 12.3, 0), pos);
  for (let t = 0; t < 60; t += 0.37) {
    const [x, y, z] = drift(pos, 1.1, t, 1);
    assert.ok(Math.abs(x - 1) <= 0.06 && Math.abs(y - 2) <= 0.16 && Math.abs(z - 3) <= 0.06);
  }
});

/* ── schedule ──────────────────────────────────────────────────────────── */

const scheduled = (root) => {
  const { hops } = walked(root);
  schedule(hops);
  return hops;
};

test("the replay starts at the root and no hop leaves before its parent arrives", () => {
  for (const root of [golden().root, chain(8), zone(...Array.from({ length: 20 }, () => step("timeout", { rtt_ms: 2000 })))]) {
    const hops = scheduled(root);
    assert.equal(hops[0].leave, 0);
    assert.equal(hops[0].at, 0.3);
    for (const hop of hops.slice(1)) {
      assert.ok(hop.leave >= hop.parent.at, `hop ${hop.id} leaves at ${hop.leave}, its parent arrives at ${hop.parent.at}`);
      assert.ok(Math.abs(hop.at - (hop.leave + hop.travel)) < 1e-9);
      assert.ok(finite([hop.leave, hop.travel, hop.at]));
    }
  }
});

test("a query takes as long as its server did, within what can be watched", () => {
  const hops = scheduled(zone(step("answer", { rtt_ms: 0.1 }), step("timeout", { rtt_ms: 5000 }), step("referral", { rtt_ms: 400 })));
  const [quick, slow, middling] = hops.slice(1).map((hop) => hop.travel);
  assert.equal(quick, 0.16);
  assert.equal(slow, 1.3);
  assert.ok(quick < middling && middling < slow);
});

test("a slow walk is squeezed into a few seconds", () => {
  const hops = scheduled(chain(10, { rtt_ms: 3000 }));
  const end = Math.max(...hops.map((hop) => hop.at));
  assert.ok(end < 12, `the replay ends at ${end}`);
});

test("a walk saved without start times is replayed one query after another", () => {
  const hops = scheduled(zone(step("timeout"), step("timeout"), step("answer")));
  const [a, b, c] = hops.slice(1);
  assert.ok(b.leave >= a.at && c.leave >= b.at);
});

test("queries that were out at once are in flight at once", () => {
  const hops = scheduled(zone(
    step("referral", { start_ms: 0, rtt_ms: 20 },
      step("timeout", { start_ms: 20, rtt_ms: 400 }),
      step("timeout", { start_ms: 20, rtt_ms: 400 }),
      step("answer", { start_ms: 21, rtt_ms: 30 })),
  ));
  const [, first, second, answer] = hops.slice(1);
  assert.equal(first.leave, second.leave);
  assert.ok(answer.leave < first.at, "the answer went out before the timeouts gave up");
  assert.ok(answer.at < first.at);
});

test("a quick query is stretched, and what it sent waits for it to arrive", () => {
  const hops = scheduled(zone(
    step("referral", { start_ms: 0, rtt_ms: 1 }, step("answer", { start_ms: 1, rtt_ms: 1 })),
  ));
  const [referral, answer] = hops.slice(1);
  assert.equal(referral.travel, 0.16);
  assert.equal(answer.leave, referral.at);
});

test("a failure without a start stands where the last thing before it finished", () => {
  const hops = scheduled(zone(
    step("referral", { start_ms: 0, rtt_ms: 300 }, step("error", { rtt_ms: undefined })),
    step("timeout", { start_ms: 0, rtt_ms: 2000 }),
  ));
  const [referral, error] = hops.slice(1);
  assert.ok(error.leave >= referral.at);
});

test("a server nobody asked appears just after the hop that named it", () => {
  const hops = scheduled(golden().root);
  const skipped = hops.find((hop) => hop.step.kind === "skipped");
  assert.ok(skipped.leave > skipped.parent.at && skipped.leave < skipped.parent.at + 0.2);
  assert.equal(skipped.travel, 0.4);
});

/* ── what a hop is called ──────────────────────────────────────────────── */

test("a hop is titled by the server that answered, or the zone it stands for", () => {
  const { hops } = walked(golden().root);
  assert.deepEqual(hops.map((hop) => titleOf(hop.step)), [
    ". root", "a.root-servers.net.", "b.gtld-servers.net.", "a.gtld-servers.net.",
    "a.iana-servers.net.", "a.iana-servers.net.", "b.iana-servers.net.",
  ]);
  assert.equal(titleOf({ kind: "zone", zone: "com." }), "com.");
  assert.equal(titleOf({ kind: "answer", zone: "com.", server: { ip: "192.0.2.1" } }), "192.0.2.1");
  assert.equal(titleOf({ kind: "error", zone: "com.", notes: ["no address", "gave up"] }), "no address; gave up");
  assert.equal(titleOf({ kind: "error", zone: "com." }), "com.");
});

test("a hop's subtitle says what it came to", () => {
  const { hops, result } = walked(golden().root);
  assert.deepEqual(hops.map((hop) => subtitleOf(hop, result)), [
    "where the walk starts",
    ". → com. · 12 ms",
    "com. · timeout · 2.00 s",
    "com. → example.com. · 18 ms",
    "A 93.184.216.34",
    "example.com. · aside · 8.0 ms",
    "example.com. · skipped",
  ]);
  const more = walked(zone(step("answer", { records: [{ type: "A", data: "192.0.2.1" }, { type: "A", data: "192.0.2.2" }, { type: "A", data: "192.0.2.3" }] })));
  assert.equal(subtitleOf(more.hops[1], more.result), "A 192.0.2.1 +2");
});

test("the inspector says what the trace recorded, and nothing it did not", () => {
  const { hops } = walked(golden().root);
  const facts = (hop) => Object.fromEntries(factsOf(hop.step).map(([term, value, tone]) => [term, [value, tone]]));

  const root = facts(hops[1]);
  assert.deepEqual(root.cookie, ["supported: answered our client cookie with one of its own", null]);
  assert.deepEqual(root.ds, ["present", "ok"]);
  assert.deepEqual(root.trust, ["insecure", "warn"]);
  assert.deepEqual(root.instance, ["fra2", null]);

  const answer = facts(hops[4]);
  assert.deepEqual(answer.size, ["1187 of 1232 bytes", "warn"]);
  assert.deepEqual(answer.flags, ["AA DO EDNS", null]);
  assert.deepEqual(answer["key tags"], ["31589", null]);
  assert.deepEqual(answer.network, ["AS10745", null]);
  assert.deepEqual(answer.prefix, ["199.43.132.0/22 · US · arin", null]);
  assert.ok(answer["signed until"]);

  const timeout = facts(hops[2]);
  assert.deepEqual(timeout.took, ["2.00 s", "warn"]);
  assert.deepEqual(timeout.error, ["udp 192.33.14.30:53: i/o timeout", "bad"]);
  for (const hop of hops) {
    for (const [term, value] of factsOf(hop.step)) assert.ok(value, `hop ${hop.id} has an empty ${term}`);
  }
});

test("the inspector marks what is wrong with a hop", () => {
  const facts = (fields) => Object.fromEntries(factsOf(step("answer", fields)).map(([term, value, tone]) => [term, [value, tone]]));
  const cases = {
    "a failing rcode": [{ rcode: "SERVFAIL" }, "rcode", ["SERVFAIL", "warn"]],
    "a cookie that is not ours": [{ cookie: "mismatch" }, "cookie", ["mismatch: answered with a client cookie other than the one sent", "bad"]],
    "a cookie state this build does not know": [{ cookie: "new" }, "cookie", ["new: ", null]],
    "a name left pointing at nothing": [{ dangling: { kind: "cname", missing: "gone.example." } }, "dangling cname", ["gone.example. is missing", "warn"]],
    "a delegation every server of is lame": [{ dangling: { kind: "lame" } }, "dangling", ["every nameserver lame", "warn"]],
    "a zone handed to anyone": [{ probe: { kind: "axfr", state: "open" } }, "axfr", ["open", "bad"]],
    "recursion that could not be checked": [{ probe: { kind: "recursion", state: "unchecked" } }, "recursion", ["unchecked", "warn"]],
    "recursion refused": [{ probe: { kind: "recursion", state: "closed" } }, "recursion", ["closed", null]],
    "an extended error withheld": [{ extended: [{ code: 15, reason: "Blocked", withheld: true }] }, "ede", ["Blocked", "warn"]],
    "a delegation without glue": [{ delegation: { zone: "a.example.", ns: ["x.", "y."], glueless: true } }, "nameservers", ["2, none with glue", null]],
  };
  for (const [name, [fields, term, want]] of Object.entries(cases)) assert.deepEqual(facts(fields)[term], want, name);
});

/* ── labels and stepping ───────────────────────────────────────────────── */

const label = (id, rank, x, y) => ({ id, place: { x, y, o: 1, rank }, box: { w: 100, h: 20 } });

test("a label that would land on a more important one is left out", () => {
  const picked = label(9, 0, 0, 0);
  const onTop = label(1, 4, 10, 5);
  const clear = label(2, 6, 0, 200);
  const hovered = label(3, 1, 5, 0);
  const showing = [onTop, clear, picked, hovered];
  declutter(showing);
  assert.deepEqual(showing.map((hop) => hop.id), [9, 3, 1, 2], "most important first");
  assert.equal(picked.place.o, 1);
  assert.equal(hovered.place.o, 1, "the hovered label is shown even over the picked one");
  assert.equal(onTop.place.o, 0);
  assert.equal(clear.place.o, 1);
});

test("of two labels the same rank, the earlier hop keeps its place", () => {
  const first = label(1, 4, 0, 0);
  const later = label(2, 4, 50, 0);
  declutter([later, first]);
  assert.equal(first.place.o, 1);
  assert.equal(later.place.o, 0);
});

test("stepping through the hops goes round at either end", () => {
  const stops = ["a", "b", "c"];
  assert.equal(stepFrom(stops, null, 1), "a");
  assert.equal(stepFrom(stops, null, -1), "c");
  assert.equal(stepFrom(stops, "a", 1), "b");
  assert.equal(stepFrom(stops, "c", 1), "a");
  assert.equal(stepFrom(stops, "a", -1), "c");
  assert.equal(stepFrom(stops, "gone", 1), "a", "a hop that is not a stop starts over");
});
