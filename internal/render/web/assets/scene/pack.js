// What the renderer is handed: every hop, thread and packet as a run of floats
// in the order the shaders read them. The renderer divides by the same strides,
// so an instance cannot grow a field on one side only.

import { TONES, trustTone, leaks } from "./walk.js";
import { add, scale, norm, mix } from "./space.js";

// Floats per instance: a node is place+size, colour+glow, and phase, spin,
// arrival and wobble; a halo is place+size, colour+glow, phase and arrival; an
// edge is both ends with their phases, colour+strength, and leave, travel,
// width and pulse; a packet is both ends, colour+size, and leave, travel and
// loop.
export const STRIDE = { node: 12, halo: 10, edge: 16, packet: 15 };

export function nodesOf(hops, glowOf) {
  const byShape = {};
  const halos = [];
  for (const hop of hops) {
    const color = TONES[hop.tone].map((c) => c * hop.dim);
    const glow = glowOf(hop);
    const spin = hop.step.kind === "zone" ? 0.25 : 0.35 + (hop.id % 5) * 0.08;
    (byShape[hop.kind.shape] ??= []).push(...hop.pos, hop.size, ...color, glow, hop.phase, spin, hop.at, 0.35);
    if (hop.step.dnssec) {
      const ring = TONES[trustTone(hop.step.dnssec.state)];
      (byShape.ring ??= []).push(...hop.pos, hop.size * 1.75, ...ring, glow * 0.5, hop.phase, 0.9, hop.at + 0.25, 1.15);
    }
    if (hop.shard) (byShape.tetra ??= []).push(...hop.shard, 0.17, ...TONES.warn, glow * 0.5, hop.phase, 2.4, hop.at + 0.6, 0.6);
    halos.push(...hop.pos, hop.size, ...color, glow, hop.phase, hop.at);
  }
  return { byShape, halos };
}

export function wiresOf(hops, { onPath, result, floor }) {
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
  // A beam under the answer, down to the floor.
  if (result) {
    edges.push(...result.pos, result.phase, result.pos[0], floor, result.pos[2], -1, ...TONES.ok, 0.3,
      result.at, 0.8, 1.2, 0.5);
  }
  return { edges, packets };
}
