// What the scene reads out of a trace: which hops there are, how each is
// named, where it floats and when it arrives. Nothing here touches the page,
// so all of it can be checked without a browser.

/* ── the vocabulary of a trace ─────────────────────────────────────────── */

// Linear RGB, since everything is added together on a dark screen.
export const TONES = {
  info:  [0.30, 0.78, 1.00],
  ok:    [0.32, 1.00, 0.66],
  warn:  [1.00, 0.70, 0.24],
  bad:   [1.00, 0.28, 0.42],
  quiet: [0.42, 0.52, 0.72],
};

export const KINDS = {
  zone:     { shape: "ico",    size: 1.05, tone: "info",  says: "the zone a walk starts from" },
  referral: { shape: "octa",   size: 0.62, tone: "info",  says: "sent the walk one zone further down" },
  answer:   { shape: "sphere", size: 0.68, tone: "ok",    says: "answered the question" },
  cname:    { shape: "torus",  size: 0.62, tone: "info",  says: "an alias, chased from here" },
  nodata:   { shape: "cube",   size: 0.52, tone: "warn",  says: "the name exists, the type does not" },
  nxdomain: { shape: "cube",   size: 0.52, tone: "warn",  says: "the name does not exist" },
  lame:     { shape: "tetra",  size: 0.6,  tone: "warn",  says: "not serving the zone it was asked about" },
  filtered: { shape: "tetra",  size: 0.6,  tone: "bad",   says: "an answer somebody decided, not one served" },
  timeout:  { shape: "tetra",  size: 0.6,  tone: "bad",   says: "said nothing in time" },
  error:    { shape: "tetra",  size: 0.6,  tone: "bad",   says: "could not be asked" },
  skipped:  { shape: "octa",   size: 0.2,  tone: "quiet", says: "known, never queried" },
};
export const kindOf = (kind) => KINDS[kind] ?? { shape: "tetra", size: 0.5, tone: "quiet", says: kind };

// The origin networks the servers sit in, told apart from each other on the
// floor in hues the tones above do not use, so a network is never read as a
// verdict.
export const NETWORKS = [
  [0.62, 0.46, 1.00],
  [0.98, 0.45, 0.85],
  [0.36, 0.92, 0.90],
  [0.55, 0.66, 1.00],
  [0.86, 0.62, 1.00],
  [0.80, 0.90, 1.00],
];

// What a comparison draws: what was there and is gone, and what is new.
export const GHOST = [0.72, 0.64, 1.00];
export const FRESH = [0.92, 0.88, 1.00];

const TRUST = { secure: "ok", insecure: "warn", bogus: "bad", indeterminate: "quiet" };
export const trustTone = (state) => TRUST[state] ?? "quiet";

const COOKIES = {
  supported: "answered our client cookie with one of its own",
  absent:    "answered without a cookie, which is allowed",
  mismatch:  "answered with a client cookie other than the one sent",
  malformed: "answered with a cookie of a length no cookie has",
  rejected:  "answered BADCOOKIE even to the cookie it handed out",
};

/* ── small tools ───────────────────────────────────────────────────────── */

export const took = (ms) => {
  if (ms === undefined || ms === null) return "";
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  if (ms >= 10) return `${Math.round(ms)} ms`;
  return `${ms.toFixed(ms < 1 ? 2 : 1)} ms`;
};

// A span of days or hours, coarsely: how long a signature had to run.
export const lasted = (ms) => {
  const hours = ms / 3_600_000;
  if (hours < 0) return "expired";
  if (hours < 48) return `${Math.floor(hours)} h`;
  return `${Math.floor(hours / 24)} days`;
};

const flagsOf = (flags) => Object.entries(flags ?? {}).filter(([, on]) => on).map(([f]) => f.toUpperCase());
export const clamp = (x, lo, hi) => Math.min(hi, Math.max(lo, x));

/* ── the walk, flattened ───────────────────────────────────────────────── */

// Every hop in the order the walk made it, which is also the order the scene
// assembles in.
export function flatten(root) {
  const hops = [];
  const visit = (step, parent, depth) => {
    if (!step) return;
    const hop = { id: hops.length, step, parent, depth, kids: [] };
    hops.push(hop);
    parent?.kids.push(hop);
    for (const child of step.children ?? []) visit(child, hop, depth + 1);
  };
  visit(root, null, 0);
  return hops;
}

export const asked = (step) => step.kind !== "zone" && step.kind !== "skipped";

// A server that hands out its zone, or looks names up, for anyone who asks.
export const leaks = (hop) => hop.step.probe?.state === "open";

// resultOf is read the way the trace defines it: the deepest hop that is
// neither an aside nor a minimised one.
export function resultOf(hop) {
  if (!hop || hop.step.aside) return null;
  let found = !hop.step.minimised && ["answer", "cname", "nodata", "nxdomain"].includes(hop.step.kind) ? hop : null;
  for (const kid of hop.kids) found = resultOf(kid) ?? found;
  return found;
}

export function verdictOf(hops, result) {
  if (hops.some((hop) => hop.step.dnssec?.state === "bogus")) return { text: "bogus", tone: "bad" };
  if (!result && hops.some((hop) => hop.step.kind === "filtered")) return { text: "filtered", tone: "bad" };
  if (!result) return { text: "no answer", tone: "warn" };
  return { text: "answered", tone: "ok" };
}

// The chain is only as good as its worst cut.
export function chainState(hops) {
  const states = hops.map((hop) => hop.step.dnssec?.state).filter(Boolean);
  return ["bogus", "indeterminate", "insecure", "secure"].find((state) => states.includes(state));
}

/* ── how long the signatures had ──────────────────────────────────────── */

// The share of the life it was made for that the stalest signature under a
// verdict had left, and how long that was, when the walk was made. It is read
// against when the walk began rather than the clock, so a walk drawn again
// says what it said then. Null where either is not known.
export function lifeOf(dnssec, started) {
  const at = Date.parse(started);
  if (Number.isNaN(at)) return null;
  let least = null;
  for (const signature of dnssec?.signatures ?? []) {
    const from = Date.parse(signature.inception);
    const to = Date.parse(signature.expiration);
    if (!(to > from)) continue;
    const share = (to - at) / (to - from);
    if (!least || share < least.share) least = { share, ms: to - at };
  }
  return least && { share: clamp(least.share, 0, 1), ms: least.ms };
}

/* ── the networks the servers sit in ─────────────────────────────────── */

// The origin networks of the servers asked, most crowded first, each with the
// hops in it and a hue of its own. A server whose AS was not found is in none.
export function networksOf(hops) {
  const byNumber = new Map();
  for (const hop of hops) {
    const as = asked(hop.step) ? hop.step.server?.asn : null;
    if (!as) continue;
    if (!byNumber.has(as.number)) byNumber.set(as.number, { number: as.number, country: as.country_code, hops: [] });
    byNumber.get(as.number).hops.push(hop);
  }
  const networks = [...byNumber.values()].sort((a, b) => b.hops.length - a.hops.length || a.number - b.number);
  networks.forEach((network, i) => {
    network.color = NETWORKS[i % NETWORKS.length];
    for (const hop of network.hops) hop.network = network;
  });
  return networks;
}

// The shortest set of lines that joins points on the floor, as pairs of
// indices: what ties the footprints of one network together. Prim's, since a
// network has a handful of servers.
export function spanning(points) {
  if (points.length < 2) return [];
  const joined = [0];
  const pairs = [];
  const far = (a, b) => Math.hypot(a[0] - b[0], a[2] - b[2]);
  while (joined.length < points.length) {
    let best = null;
    for (const from of joined) {
      for (let to = 0; to < points.length; to++) {
        if (joined.includes(to)) continue;
        const d = far(points[from], points[to]);
        if (!best || d < best.d) best = { from, to, d };
      }
    }
    pairs.push([best.from, best.to]);
    joined.push(best.to);
  }
  return pairs;
}

/* ── what changed since another walk ───────────────────────────────────── */

const named = (name) => {
  const lower = String(name ?? "").toLowerCase();
  return lower.endsWith(".") ? lower : `${lower}.`;
};

// The hop where the walk crossed into a zone: the referral that sent it
// there, or the start for the root.
export function cutOf(hops, zone) {
  const name = named(zone);
  if (name === ".") return hops[0];
  return hops.find((hop) => !hop.step.aside && named(hop.step.delegation?.zone) === name) ?? null;
}

// The cut nearest above a zone the walk no longer crosses, which is where the
// ghost of it hangs.
function above(hops, zone) {
  let name = named(zone);
  while (name !== ".") {
    name = name.slice(name.indexOf(".") + 1) || ".";
    const cut = cutOf(hops, name);
    if (cut) return cut;
  }
  return hops[0];
}

// What --diff or --against found, put where it happened. Each mark is a hop
// with what changed about it, and the fresh ones are those with something new
// in them; each ghost is something the other walk had that
// this one does not, hung off the hop nearest to where it was; each ring is a
// chain of trust that read differently then. The comparison itself is made
// when the walk is remembered: this only finds where to draw it.
export function changesOf(hops, changes, result) {
  const marks = new Map();
  const fresh = new Set();
  const ghosts = [];
  const rings = [];
  if (!changes) return { marks, fresh, ghosts, rings };
  const mark = (hop, text) => hop && marks.set(hop, [...(marks.get(hop) ?? []), text]);
  const anew = (hop, text) => hop && fresh.add(hop) && mark(hop, text);

  for (const zone of changes.zones ?? []) {
    if (zone.went) {
      ghosts.push({ anchor: above(hops, zone.name), shape: "ico", title: zone.name, text: "a cut the walk crosses no longer" });
      continue;
    }
    const cut = cutOf(hops, zone.name);
    if (zone.came) anew(cut, "a zone cut that was not there");
    for (const ns of zone.ns_came ?? []) {
      const server = cut?.kids.find((kid) => named(kid.step.server?.name) === named(ns));
      anew(server ?? cut, server ? `new among the nameservers of ${zone.name}` : `${ns} is new among its nameservers`);
    }
    for (const ns of zone.ns_went ?? []) {
      if (cut) ghosts.push({ anchor: cut, shape: "octa", title: ns, text: `dropped from the nameservers of ${zone.name}` });
    }
    if (zone.dnssec_was) {
      const judged = hops.find((hop) => named(hop.step.dnssec?.zone) === named(zone.name));
      if (judged) rings.push({ hop: judged, was: zone.dnssec_was });
      mark(judged ?? cut, `the chain of trust read ${zone.dnssec_was} then`);
    }
  }

  if (changes.was) {
    const { kind, answer = [] } = changes.was;
    const said = answer.length ? `${answer[0]}${answer.length > 1 ? ` +${answer.length - 1}` : ""}` : kind || "no answer";
    const anchor = result ?? hops.findLast((hop) => !hop.step.aside) ?? hops[0];
    ghosts.push({ anchor, shape: kindOf(kind || "timeout").shape, title: said, text: "the answer then" });
  }

  // Ghosts sharing a hop fan out beneath it, away from the middle of the cone.
  const byAnchor = Map.groupBy(ghosts, (ghost) => ghost.anchor);
  for (const [anchor, group] of byAnchor) {
    const out = Math.hypot(anchor.pos[0], anchor.pos[2]) > 0.1 ? Math.atan2(anchor.pos[2], anchor.pos[0]) : 0;
    group.forEach((ghost, i) => {
      const a = out + (i - (group.length - 1) / 2) * 0.55;
      ghost.pos = [anchor.pos[0] + Math.cos(a) * 1.7, anchor.pos[1] - 1.3 - (i % 2) * 0.35, anchor.pos[2] + Math.sin(a) * 1.7];
    });
  }
  ghosts.forEach((ghost, i) => { ghost.phase = ((i + 1000) * 2.399963) % (Math.PI * 2); });
  return { marks, fresh, ghosts, rings };
}

// How many things changed, counted the way the sentences under the walk say
// them: a cut that came or went, its nameservers, its chain, and the answer or
// its TTL.
export const changeCount = (changes) => (changes?.was || changes?.ttl_was ? 1 : 0) + (changes?.zones ?? []).reduce((sum, zone) =>
  sum + (zone.came || zone.went ? 1 : 0) + (zone.ns_came?.length || zone.ns_went?.length ? 1 : 0) + (zone.dnssec_was ? 1 : 0), 0);

/* ── the view, in the address ──────────────────────────────────────────── */

// Where the camera is and which hop is picked, written into the part of the
// address after the #, which never leaves the browser, so a link opens on the
// same shot.
export function viewToHash({ yaw, pitch, dist, target }, picked) {
  const view = [around(yaw), pitch, dist, ...target].map((n) => n.toFixed(3)).join(",");
  return `v=${view}${picked ? `&h=${picked.id}` : ""}`;
}

// The view a hash names, or null for one that names none. Anyone can write an
// address, so every number is checked and held within what the controls
// allow.
export function viewFromHash(hash, hops) {
  const params = new URLSearchParams(String(hash ?? "").replace(/^#/, ""));
  const numbers = (params.get("v") ?? "").split(",").map(Number);
  if (numbers.length !== 6 || !numbers.every(Number.isFinite)) return null;
  const [yaw, pitch, dist, ...target] = numbers;
  if (target.some((n) => Math.abs(n) > 500)) return null;
  const id = Number(params.get("h") ?? NaN);
  return {
    yaw: around(yaw), pitch: clamp(pitch, -1.25, 1.35), dist: clamp(dist, 4, 140), target,
    hop: Number.isInteger(id) && id >= 0 && id < hops.length ? hops[id] : null,
  };
}

/* ── where each hop floats ─────────────────────────────────────────────── */

// A cone that opens downwards: each zone cut is a level lower and a ring wider.
// Every hop is given a slice of its parent's in proportion to the angle its
// subtree needs at its most crowded ring, so a deep subtree cannot squeeze its
// shallow siblings together; when the whole circle is not enough, the rings
// grow until it is.
const LEVEL = 2.7;
const RING = 2.6;

export const widthOf = (step) => step.dnssec ? 2.5 : step.kind === "skipped" ? 0.6 : step.aside ? 1.2 : 1.7;

export function layout(hops) {
  const depths = Math.max(...hops.map((hop) => hop.depth)) + 1;
  let radii = Array.from({ length: depths }, (_, depth) => depth * RING);

  const measure = (hop) => {
    const own = hop.depth ? widthOf(hop.step) / radii[hop.depth] : 0;
    hop.need = Math.max(own, hop.kids.reduce((sum, kid) => sum + measure(kid), 0));
    return hop.need;
  };
  // The levels grow with the rings, though by less, so that a crowded walk is
  // still a cone rather than a plate.
  const grown = Math.max(1, measure(hops[0]) / (Math.PI * 2));
  if (grown > 1) {
    radii = radii.map((r) => r * grown);
    measure(hops[0]);
  }
  const level = LEVEL * Math.sqrt(grown);

  const place = (hop, from, to) => {
    const angle = (from + to) / 2;
    const radius = radii[hop.depth];
    hop.pos = [radius * Math.cos(angle), -hop.depth * level, radius * Math.sin(angle)];
    const total = hop.kids.reduce((sum, kid) => sum + kid.need, 0);
    let at = from;
    for (const kid of hop.kids) {
      const span = (to - from) * kid.need / total;
      place(kid, at, at + span);
      at += span;
    }
  };
  place(hops[0], -Math.PI / 2, Math.PI * 1.5);

  const lowest = -(depths - 1) * level;
  for (const hop of hops) hop.pos[1] -= lowest / 2;

  // The camera is aimed at where the hops are, which is not the middle of the
  // rings when most of the walk went one way.
  const xs = hops.map((hop) => hop.pos[0]);
  const zs = hops.map((hop) => hop.pos[2]);
  const centre = [(Math.min(...xs) + Math.max(...xs)) / 2, 0, (Math.min(...zs) + Math.max(...zs)) / 2];
  return {
    radius: radii.at(-1),
    centre,
    spread: Math.max(...hops.map((hop) => Math.hypot(hop.pos[0] - centre[0], hop.pos[2] - centre[2]))),
    height: -lowest,
    floor: lowest / 2 - 2.2,
  };
}

// Where a hop is at a moment: floating about the place it was given. The
// shaders do the same sums, so that the labels and the picking agree with what
// is drawn.
export const drift = (pos, phase, time, motion) => [
  pos[0] + motion * Math.cos(time * 0.53 + phase * 1.7) * 0.06,
  pos[1] + motion * Math.sin(time * 0.9 + phase) * 0.16,
  pos[2] + motion * Math.sin(time * 0.61 + phase * 2.3) * 0.06,
];

/* ── when each hop arrives ─────────────────────────────────────────────── */

// The walk is replayed as it was made, each query leaving when it left and
// taking as long as its server took, squeezed so that a slow walk still
// assembles in a few seconds: queries that were out at once are in flight at
// once. A failure has no start of its own, so it stands where the last thing
// before it finished, as it does on the waterfall. A walk saved before steps
// carried their start is replayed one query after another. The times are on
// the replay's own clock, which starts at 0.
export function schedule(hops) {
  const queries = hops.filter((hop) => asked(hop.step));
  const timed = queries.some((hop) => hop.step.start_ms !== undefined);
  const span = timed
    ? Math.max(...queries.map((hop) => (hop.step.start_ms ?? 0) + (hop.step.rtt_ms ?? 0)))
    : queries.reduce((sum, hop) => sum + (hop.step.rtt_ms ?? 0), 0);
  const perMs = Math.min(0.0028, 7.5 / Math.max(span, 1));

  let clock = 0.9;
  let latest = clock;
  hops[0].leave = 0;
  hops[0].travel = 0.01;
  hops[0].at = 0.3;
  for (const hop of hops.slice(1)) {
    if (asked(hop.step)) {
      hop.travel = clamp((hop.step.rtt_ms ?? 0) * perMs, 0.16, 1.3);
      const started = timed && hop.step.start_ms !== undefined;
      const left = started ? 0.9 + hop.step.start_ms * perMs : timed ? latest : clock;
      // Squeezing stretches the quick queries, so a hop may not leave before
      // the one that sent it has visibly arrived.
      hop.leave = Math.max(left, hop.parent.at);
      clock = hop.at = hop.leave + hop.travel;
      latest = Math.max(latest, hop.at);
    } else {
      const sibling = hop.parent.kids.indexOf(hop);
      hop.travel = 0.4;
      hop.leave = hop.parent.at + 0.05 + sibling * 0.025;
      hop.at = hop.leave + hop.travel;
    }
  }
}

/* ── riding along ──────────────────────────────────────────────────────── */

// The way from the root to where the walk ended, root first, which is what
// the camera rides down. Empty when the walk came to nothing.
export function trailOf(result) {
  const trail = [];
  for (let hop = result; hop; hop = hop.parent) trail.unshift(hop);
  return trail.length > 1 ? trail : [];
}

// Where the question is on the trail at a moment of the replay: gliding
// between two hops the way its packet does, or waiting at the last it reached.
// heading is the way it is going, flat, and since how long ago it last reached
// a hop, for the camera to lean into the cut.
export function rideAt(trail, t, time, motion) {
  let i = 1;
  while (i < trail.length - 1 && trail[i].at <= t) i++;
  const from = trail[i - 1];
  const to = trail[i];
  const k = clamp((t - to.leave) / to.travel, 0, 1);
  const e = k * k * (3 - 2 * k);
  const a = drift(from.pos, from.phase, time, motion);
  const b = drift(to.pos, to.phase, time, motion);
  return {
    at: a.map((v, n) => v + (b[n] - v) * e),
    ahead: b,
    heading: [to.pos[0] - from.pos[0], 0, to.pos[2] - from.pos[2]],
    since: Math.max(0, t - (k >= 1 ? to.at : from.at)),
    done: t >= to.at && i === trail.length - 1,
  };
}

// When the answer arrives, a bead runs back up the trail to the root, one hop
// after another and in about a second however deep the walk went. Each leg
// goes from a hop to the one that sent the walk to it.
export function landingOf(trail) {
  if (!trail.length) return [];
  const travel = Math.min(0.25, 0.9 / (trail.length - 1));
  const start = trail.at(-1).at + 0.15;
  return trail.slice(1).reverse().map((hop, i) => ({ from: hop, to: hop.parent, leave: start + i * travel, travel }));
}

// The yaw that puts the camera behind something going this way.
export const behind = ([x, , z]) => Math.atan2(-x, -z);

// An angle brought into (-π, π], so the camera turns the short way round.
export const around = (a) => Math.atan2(Math.sin(a), Math.cos(a));

/* ── what a hop is called ──────────────────────────────────────────────── */

export function titleOf(step) {
  if (step.kind === "zone") return step.zone === "." ? ". root" : step.zone;
  if (!step.server) return step.notes?.join("; ") ?? step.zone;
  return step.server.name ?? step.server.ip;
}

export function subtitleOf(hop, result) {
  const { step } = hop;
  if (step.kind === "zone") return "where the walk starts";
  if (hop === result && step.records?.length) {
    const first = step.records[0];
    return `${first.type} ${first.data}${step.records.length > 1 ? ` +${step.records.length - 1}` : ""}`;
  }
  if (step.kind === "referral" && step.delegation?.zone) return `${step.zone} → ${step.delegation.zone} · ${took(step.rtt_ms)}`;
  return [step.zone, step.aside ? "aside" : step.kind, took(step.rtt_ms)].filter(Boolean).join(" · ");
}

// The rows the inspector shows for a hop, as [term, value, tone]. A row with
// nothing to say is left out.
export function factsOf(step, started) {
  const rows = [];
  const row = (term, value, tone) => value && rows.push([term, value, tone ?? null]);
  row("zone", step.zone);
  if (step.asked) row("asked", `${step.asked.name} ${step.asked.type}`);
  if (step.minimised) row("minimised", "asked only enough to find the next cut");
  row("over", step.proto);
  row("took", took(step.rtt_ms), step.rtt_ms > 500 ? "warn" : null);
  if (step.size_bytes) row("size", step.limit_bytes ? `${step.size_bytes} of ${step.limit_bytes} bytes` : `${step.size_bytes} bytes`, step.tight ? "warn" : null);
  row("rcode", step.rcode, step.rcode && step.rcode !== "NOERROR" ? "warn" : null);
  row("flags", flagsOf(step.flags).join(" "));
  if (step.delegation) {
    const d = step.delegation;
    row("sends to", d.zone);
    row("nameservers", `${d.ns?.length ?? 0}${d.glueless ? ", none with glue" : ""}`);
    row("ds", d.ds_present ? "present" : "none", d.ds_present ? "ok" : null);
  }
  if (step.dnssec) {
    const s = step.dnssec;
    row("trust", s.state, trustTone(s.state));
    row("algorithm", [s.algorithm, s.digest].filter(Boolean).join(" · "));
    if (s.key_tags?.length) row("key tags", s.key_tags.join(", "));
    const expires = s.signatures?.map((sig) => sig.expiration).sort()[0];
    if (expires) row("signed until", new Date(expires).toLocaleString());
    const life = lifeOf(s, started);
    if (life) row("life left", `${Math.round(life.share * 100)}% · ${lasted(life.ms)}`);
    row("because", s.reason);
  }
  if (step.server?.asn) {
    const as = step.server.asn;
    row("network", `AS${as.number}`);
    row("prefix", [as.prefix, as.country_code, as.registry].filter(Boolean).join(" · "));
  }
  row("instance", step.nsid);
  const said = step.server?.software;
  if (said) row("software", said.version ? `"${said.version}"` : "hidden");
  if (step.cookie) row("cookie", `${step.cookie}: ${COOKIES[step.cookie] ?? ""}`, ["mismatch", "rejected"].includes(step.cookie) ? "bad" : null);
  if (step.subnet) row("subnet", `${step.subnet.prefix} /${step.subnet.scope}`);
  if (step.soa) row("soa serial", String(step.soa.serial));
  for (const e of step.extended ?? []) row("ede", [e.reason || e.code, e.text].filter(Boolean).join(": "), e.withheld ? "warn" : null);
  const d = step.dangling;
  if (d) row(d.kind === "lame" ? "dangling" : `dangling ${d.kind}`, d.kind === "lame" ? "every nameserver lame" : `${d.missing} is missing`, "warn");
  if (step.probe) {
    row(step.probe.kind === "recursion" ? "recursion" : "axfr", step.probe.state, { open: "bad", unchecked: "warn" }[step.probe.state]);
  }
  if (step.edns) {
    const e = step.edns;
    row(`edns ${e.kind}`, [e.state, e.fault].filter(Boolean).join(": "), { broken: "bad", unchecked: "warn" }[e.state]);
  }
  row("error", step.error, "bad");
  row("notes", step.notes?.join("; "));
  return rows;
}

/* ── which labels are shown ────────────────────────────────────────────── */

// Labels are laid down most important first, and one that would land on a
// label already down is left out until the scene turns and there is room. The
// picked and the hovered hop, ranks 0 and 1, are always shown. Each hop is
// given as { id, place: { x, y, o, rank }, box: { w, h } }, and a label left
// out has its place.o set to 0.
export function declutter(showing) {
  showing.sort((a, b) => a.place.rank - b.place.rank || a.id - b.id);
  const taken = [];
  for (const hop of showing) {
    const { x, y, rank } = hop.place;
    const box = [x - 16, y - hop.box.h / 2 - 2, x + hop.box.w + 4, y + hop.box.h / 2 + 2];
    if (rank > 1 && taken.some((t) => box[0] < t[2] && box[2] > t[0] && box[1] < t[3] && box[3] > t[1])) {
      hop.place.o = 0;
    } else {
      taken.push(box);
    }
  }
}

// The stop `by` hops on from the one picked, going round at either end. With
// nothing picked, forwards starts at the first and backwards at the last.
export function stepFrom(stops, picked, by) {
  const from = picked ? stops.indexOf(picked) : -1;
  const at = from === -1 ? (by > 0 ? 0 : stops.length - 1) : (from + by + stops.length) % stops.length;
  return stops[at];
}
