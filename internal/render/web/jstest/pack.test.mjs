import { test } from "node:test";
import assert from "node:assert/strict";

import { KINDS, flatten, resultOf, layout, schedule } from "../assets/scene/walk.js";
import { STRIDE, nodesOf, wiresOf } from "../assets/scene/pack.js";
import { golden, zone, step } from "./fixtures.mjs";

// The scene does this to every hop before it packs anything.
function prepared(root) {
  const hops = flatten(root);
  const result = resultOf(hops[0]);
  const onPath = new Set();
  for (let hop = result; hop; hop = hop.parent) onPath.add(hop);
  for (const hop of hops) {
    hop.kind = KINDS[hop.step.kind];
    hop.tone = hop.kind.tone;
    hop.phase = hop.id;
    hop.size = hop.kind.size;
    hop.dim = 1;
  }
  const bounds = layout(hops);
  for (const hop of hops) if (hop.step.dangling) hop.shard = [hop.pos[0], hop.pos[1] - 1.9, hop.pos[2]];
  schedule(hops);
  return { hops, result, onPath, floor: bounds.floor };
}

const everything = () => prepared(zone(
  step("referral", { dnssec: { state: "secure" }, dangling: { kind: "cname", missing: "gone." } },
    step("answer", { probe: { kind: "axfr", state: "open" } }),
    step("skipped"),
    step("timeout", { aside: true })),
));

const whole = (data, stride) => data.length > 0 && data.length % stride === 0 && data.every(Number.isFinite);

test("every run of floats is whole instances of real numbers", () => {
  for (const [name, walk] of Object.entries({ "the golden walk": prepared(golden().root), "every hazard at once": everything() })) {
    const { byShape, halos } = nodesOf(walk.hops, () => 0.5);
    const { edges, packets } = wiresOf(walk.hops, walk);
    for (const [shape, data] of Object.entries(byShape)) assert.ok(whole(data, STRIDE.node), `${name}: ${shape}`);
    assert.ok(whole(halos, STRIDE.halo), `${name}: halos`);
    assert.ok(whole(edges, STRIDE.edge), `${name}: edges`);
    assert.ok(whole(packets, STRIDE.packet), `${name}: packets`);
  }
});

test("each hop is one node and one halo, and a signed one wears a ring", () => {
  const { hops } = prepared(golden().root);
  const { byShape, halos } = nodesOf(hops, () => 0);
  const count = (shape) => (byShape[shape]?.length ?? 0) / STRIDE.node;
  assert.equal(halos.length / STRIDE.halo, hops.length);
  assert.equal(count("ring"), hops.filter((hop) => hop.step.dnssec).length);
  assert.equal(count("sphere"), hops.filter((hop) => hop.step.kind === "answer").length);
});

test("the glow a hop is given reaches the card", () => {
  const { hops } = prepared(golden().root);
  const lit = hops[4];
  const { halos } = nodesOf(hops, (hop) => (hop === lit ? 1.3 : 0));
  const glow = (hop) => halos[hop.id * STRIDE.halo + 7];
  assert.equal(glow(lit), 1.3);
  assert.equal(glow(hops[1]), 0);
});

test("a thread for each hop but the root, a packet for each query, and a beam under the answer", () => {
  const walk = prepared(golden().root);
  const { edges, packets } = wiresOf(walk.hops, walk);
  const unasked = walk.hops.filter((hop) => hop.step.kind === "skipped").length;
  const threads = walk.hops.length - 1;
  assert.equal(edges.length / STRIDE.edge, threads + 1, "and one for the beam");
  assert.equal(packets.length / STRIDE.packet, walk.hops.length - 1 - unasked);
  const beam = edges.slice(-STRIDE.edge);
  assert.equal(beam[5], walk.floor, "the beam ends on the floor");
});

test("a dangling name snaps a thread in two, and an open server throws sparks", () => {
  const walk = everything();
  const plain = prepared(zone(step("referral", { dnssec: { state: "secure" } }, step("answer"), step("skipped"), step("timeout", { aside: true }))));
  const a = wiresOf(walk.hops, walk);
  const b = wiresOf(plain.hops, plain);
  assert.equal((a.edges.length - b.edges.length) / STRIDE.edge, 2);
  assert.equal((a.packets.length - b.packets.length) / STRIDE.packet, 7);
});
