import { test } from "node:test";
import assert from "node:assert/strict";

import {
  KINDS, TONES, GHOST, flatten, resultOf, layout, schedule, trailOf, landingOf, lifeOf, networksOf, changesOf,
} from "../assets/scene/walk.js";
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

test("the landing is a packet for each leg back up the trail, in the answer's colour", () => {
  const walk = prepared(golden().root);
  const landing = landingOf(trailOf(walk.result));
  const without = wiresOf(walk.hops, walk).packets;
  const packets = wiresOf(walk.hops, { ...walk, landing }).packets;
  assert.equal((packets.length - without.length) / STRIDE.packet, landing.length);
  const first = packets.slice(without.length, without.length + STRIDE.packet);
  assert.deepEqual(first.slice(0, 3), landing[0].from.pos);
  assert.deepEqual(first.slice(4, 7), landing[0].to.pos);
  assert.deepEqual(first.slice(8, 11), TONES.ok);
  assert.deepEqual(first.slice(12), [landing[0].leave, landing[0].travel, 0]);
});

test("a dangling name snaps a thread in two, and an open server throws sparks", () => {
  const walk = everything();
  const plain = prepared(zone(step("referral", { dnssec: { state: "secure" } }, step("answer"), step("skipped"), step("timeout", { aside: true }))));
  const a = wiresOf(walk.hops, walk);
  const b = wiresOf(plain.hops, plain);
  assert.equal((a.edges.length - b.edges.length) / STRIDE.edge, 2);
  assert.equal((a.packets.length - b.packets.length) / STRIDE.packet, 7);
});

// The fields of each instance of a shape, one array apiece.
const instances = (data, stride) => Array.from({ length: data.length / stride }, (_, i) => data.slice(i * stride, (i + 1) * stride));
const ARC = 12, GHOSTLY = 13, RIPPLE = 14;

test("a signed hop's ring is left as much unburnt as its signatures had life", () => {
  const document = golden();
  const walk = prepared(document.root);
  for (const hop of walk.hops) hop.life = lifeOf(hop.step.dnssec, document.started)?.share ?? null;
  const rings = instances(nodesOf(walk.hops, () => 0).byShape.ring, STRIDE.node);
  const signed = walk.hops.filter((hop) => hop.step.dnssec);
  assert.equal(rings.length, signed.length);
  rings.forEach((ring, i) => assert.equal(ring[ARC], signed[i].life ?? 1));
  assert.ok(rings.some((ring) => Math.abs(ring[ARC] - 6 / 14) < 1e-9), "the golden walk has one six days from fourteen");
  for (const shape of ["ico", "octa", "sphere"]) {
    for (const node of instances(nodesOf(walk.hops, () => 0).byShape[shape], STRIDE.node)) {
      assert.deepEqual(node.slice(ARC), [1, 0, 0, 0], `${shape} is whole, solid and still`);
    }
  }
});

// A walk whose servers answer from two networks, three of them from one.
const networked = () => {
  const as = (number) => ({ server: { name: `ns.as${number}.`, ip: "192.0.2.1", asn: { number } } });
  const walk = prepared(zone(step("referral", as(64500), step("answer", as(64501)), step("answer", as(64501)), step("answer", as(64501)))));
  return { ...walk, networks: networksOf(walk.hops) };
};

test("every server stands on the floor in its network's colour", () => {
  const walk = networked();
  const bare = nodesOf(walk.hops, () => 0);
  const { byShape, halos } = nodesOf(walk.hops, () => 0, walk);
  const feet = instances(byShape.ring, STRIDE.node).slice(instances(bare.byShape.ring ?? [], STRIDE.node).length);
  assert.equal(feet.length, 2 * 4, "two rings for each of the four servers");
  for (const foot of feet) assert.equal(foot[1], walk.floor);
  assert.deepEqual(feet[0].slice(4, 7), walk.networks[0].color);
  assert.equal((halos.length - bare.halos.length) / STRIDE.halo, 4);
});

test("a network's footprints are tied together, each under a thread from its server", () => {
  const walk = networked();
  const bare = wiresOf(walk.hops, { ...walk, networks: [] }).edges;
  const edges = instances(wiresOf(walk.hops, walk).edges, STRIDE.edge).slice(bare.length / STRIDE.edge);
  // Four plumb lines, and two lines joining the three of the crowded network.
  assert.equal(edges.length, 4 + 2);
  for (const edge of edges) assert.equal(edge[5], walk.floor, "every one ends on the floor");
});

test("the network looked at is the one lit", () => {
  const walk = networked();
  const crowded = walk.networks[0];
  const { byShape } = nodesOf(walk.hops, () => 0, { ...walk, lit: (network) => (network === crowded ? 0.9 : 0) });
  const glows = instances(byShape.ring, STRIDE.node).map((ring) => [ring.slice(4, 7).join(), ring[7]]);
  assert.ok(glows.some(([color, glow]) => color === crowded.color.join() && glow > 1));
  assert.ok(!glows.some(([color, glow]) => color === walk.networks[1].color.join() && glow > 1));
});

test("a ghost is drawn as an outline, hung by a dashed thread", () => {
  const walk = prepared(golden().root);
  const changes = changesOf(walk.hops, {
    zones: [{ name: "com.", ns_went: ["gone.example."] }, { name: "example.com.", ns_came: ["new.example."], dnssec_was: "insecure" }],
  }, walk.result);
  const bare = nodesOf(walk.hops, () => 0);
  const { byShape } = nodesOf(walk.hops, () => 0, { ...walk, changes });
  const ghost = instances(byShape.octa, STRIDE.node).find((node) => node[GHOSTLY] === 1);
  assert.deepEqual(ghost.slice(0, 3), changes.ghosts[0].pos);
  assert.deepEqual(ghost.slice(4, 7), GHOST);

  const added = instances(byShape.ring, STRIDE.node).slice(bare.byShape.ring.length / STRIDE.node);
  assert.equal(added.length, 2, "the chain as it read then, and the cut with something new in it");
  assert.deepEqual(added.map((ring) => [ring[GHOSTLY], ring[RIPPLE]]), [[1, 1], [0, 1]]);
  assert.deepEqual(added[0].slice(4, 7), TONES.warn, "in the colour the chain read then");

  const threads = instances(wiresOf(walk.hops, { ...walk, changes }).edges, STRIDE.edge)
    .slice(wiresOf(walk.hops, walk).edges.length / STRIDE.edge);
  assert.equal(threads.length, 1);
  assert.ok(threads[0][14] < 0, "dashed");
});

test("the whole scene with every new thing in it is still whole instances", () => {
  const walk = networked();
  const changes = changesOf(walk.hops, { was: { kind: "nxdomain" }, zones: [{ name: ".", dnssec_was: "secure" }] }, walk.result);
  const { byShape, halos } = nodesOf(walk.hops, () => 0.5, { ...walk, changes });
  const { edges, packets } = wiresOf(walk.hops, { ...walk, changes });
  for (const [shape, data] of Object.entries(byShape)) assert.ok(whole(data, STRIDE.node), shape);
  assert.ok(whole(halos, STRIDE.halo));
  assert.ok(whole(edges, STRIDE.edge));
  assert.ok(whole(packets, STRIDE.packet));
});
