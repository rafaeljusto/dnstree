// What the renderer is handed: every hop, thread and packet as a run of floats
// in the order the shaders read them. The renderer divides by the same strides,
// so an instance cannot grow a field on one side only.

import { TONES, GHOST, FRESH, trustTone, leaks, spanning } from "./walk.js";
import { add, scale, norm, mix } from "./space.js";

// Floats per instance: a node is place+size, colour+glow, phase, spin, arrival
// and wobble, and how much of a ring is left unburnt, whether it is a ghost and
// whether it ripples; a halo is place+size, colour+glow, phase and arrival; an
// edge is both ends with their phases, colour+strength, and leave, travel,
// width and pulse; a packet is both ends, colour+size, and leave, travel and
// loop.
export const STRIDE = { node: 16, halo: 10, edge: 16, packet: 15 };

// A phase of -1 holds a thing still where the others float: the floor does not.
const STILL = -1;

// The floor under a hop, where its footprint is.
export const under = (pos, floor) => [pos[0], floor, pos[2]];

export function nodesOf(hops, glowOf, { networks = [], floor = 0, lit = () => 0, changes = null } = {}) {
  const byShape = {};
  const halos = [];
  const put = (shape, pos, size, color, glow, phase, spin, at, wobble, { arc = 1, ghost = 0, ripple = 0 } = {}) =>
    (byShape[shape] ??= []).push(...pos, size, ...color, glow, phase, spin, at, wobble, arc, ghost, ripple, 0);

  for (const hop of hops) {
    const color = TONES[hop.tone].map((c) => c * hop.dim);
    const glow = glowOf(hop);
    const spin = hop.step.kind === "zone" ? 0.25 : 0.35 + (hop.id % 5) * 0.08;
    put(hop.kind.shape, hop.pos, hop.size, color, glow, hop.phase, spin, hop.at, 0.35);
    // The ring burns down to what was left of the signatures' life.
    if (hop.step.dnssec) {
      const ring = TONES[trustTone(hop.step.dnssec.state)];
      put("ring", hop.pos, hop.size * 1.75, ring, glow * 0.5, hop.phase, 0.9, hop.at + 0.25, 1.15, { arc: hop.life ?? 1 });
    }
    if (hop.shard) put("tetra", hop.shard, 0.17, TONES.warn, glow * 0.5, hop.phase, 2.4, hop.at + 0.6, 0.6);
    halos.push(...hop.pos, hop.size, ...color, glow, hop.phase, hop.at);
  }

  // Each server stands on the floor in the colour of its network: two rings
  // and a glow, brighter while one of its network is looked at.
  for (const network of networks) {
    const glow = lit(network);
    for (const hop of network.hops) {
      const foot = under(hop.pos, floor);
      put("ring", foot, 0.42, network.color, 0.3 + glow, STILL, 0.2, hop.at + 0.35, 0);
      put("ring", foot, 0.75, network.color.map((c) => c * 0.45), glow * 0.5, STILL, -0.12, hop.at + 0.5, 0);
      halos.push(...foot, 0.28, ...network.color, 0.2 + glow, STILL, hop.at + 0.35);
    }
  }

  if (changes) {
    for (const ghost of changes.ghosts) {
      put(ghost.shape, ghost.pos, 0.5, GHOST, 0.4, ghost.phase, 0.5, ghost.anchor.at + 0.6, 0.35, { ghost: 1 });
    }
    // The chain as it read then, rippling out from the ring that reads
    // otherwise now.
    for (const { hop, was } of changes.rings) {
      put("ring", hop.pos, hop.size * 2.1, TONES[trustTone(was)], 0.3, hop.phase, 0.5, hop.at + 0.5, 1.15, { ghost: 1, ripple: 1 });
    }
    for (const hop of changes.fresh) {
      put("ring", hop.pos, hop.size * 1.5, FRESH, 0.6, hop.phase, 0.3, hop.at + 0.4, 0.5, { ripple: 1 });
    }
  }
  return { byShape, halos };
}

export function wiresOf(hops, { onPath, result, floor, landing = [], networks = [], changes = null }) {
  const edges = [];
  const packets = [];
  for (const hop of hops.slice(1)) {
    const path = onPath.has(hop);
    const color = TONES[hop.tone];
    const skipped = hop.step.kind === "skipped";
    const strength = path ? 0.9 : skipped ? 0.14 : hop.step.aside ? 0.28 : 0.42;
    const width = path ? 2.6 : skipped ? 0.9 : 1.5;
    edges.push(...hop.parent.pos, hop.parent.phase, ...hop.pos, hop.phase, ...color, strength,
      hop.leave, hop.travel, width, path ? 0.35 : 0);
    if (!skipped) packets.push(...hop.parent.pos, hop.parent.phase, ...hop.pos, hop.phase, ...color, path ? 0.9 : 0.6, hop.leave, hop.travel, 0);
  }
  for (const hop of hops) {
    // The thread breaks short of its shard, and something drains down it.
    if (hop.shard) {
      edges.push(...hop.pos, hop.phase, ...mix(hop.pos, hop.shard, 0.6), hop.phase, ...TONES.warn, 0.5, hop.at + 0.1, 0.5, 1.1, 0.5);
      edges.push(...mix(hop.pos, hop.shard, 0.76), hop.phase, ...hop.shard, hop.phase, ...TONES.warn, 0.35, hop.at + 0.45, 0.3, 0.8, 0);
    }
    // Sparks thrown off a server that hands out its zone, or looks names up,
    // for anyone who asks.
    if (leaks(hop)) {
      for (let i = 0; i < 7; i++) {
        const a = hop.phase + i * 2.399963;
        const to = add(hop.pos, scale(norm([Math.cos(a), (i % 3) * 0.35 - 0.1, Math.sin(a)]), 1.5));
        packets.push(...hop.pos, hop.phase, ...to, -1, ...TONES.bad, 0.45, hop.at + 0.2, 1.4 + (i % 3) * 0.3, (i + 1) / 8);
      }
    }
  }
  for (const leg of landing) {
    packets.push(...leg.from.pos, leg.from.phase, ...leg.to.pos, leg.to.phase, ...TONES.ok, 1.1, leg.leave, leg.travel, 0);
  }
  // A beam under the answer, down to the floor.
  if (result) {
    edges.push(...result.pos, result.phase, result.pos[0], floor, result.pos[2], -1, ...TONES.ok, 0.3,
      result.at, 0.8, 1.2, 0.5);
  }
  // A thread down from each server to its footprint, and lines along the
  // floor tying the footprints of one network together.
  for (const network of networks) {
    for (const hop of network.hops) {
      edges.push(...hop.pos, hop.phase, ...under(hop.pos, floor), STILL, ...network.color, 0.09, hop.at + 0.1, 0.7, 0.7, 0);
    }
    const feet = network.hops.map((hop) => under(hop.pos, floor));
    for (const [a, b] of spanning(feet)) {
      const from = network.hops[a];
      const to = network.hops[b];
      edges.push(...feet[a], STILL, ...feet[b], STILL, ...network.color, 0.32,
        Math.max(from.at, to.at) + 0.45, 0.9, 1.3, 0.12);
    }
  }
  // A ghost hangs from where it was by a broken thread: a negative width is
  // drawn dashed.
  for (const ghost of changes?.ghosts ?? []) {
    edges.push(...ghost.anchor.pos, ghost.anchor.phase, ...ghost.pos, ghost.phase, ...GHOST, 0.35,
      ghost.anchor.at + 0.3, 0.6, -1.1, 0);
  }
  return { edges, packets };
}
