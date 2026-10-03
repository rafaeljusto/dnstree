// What the page reads out of a trace: which hops there are, what each is
// called and what it wears. Nothing here touches the page, so all of it can be
// checked without a browser.

/* ── the vocabulary of a trace ─────────────────────────────────────────── */

// What each kind of hop is called, drawn with, and coloured by.
export const KINDS = {
  zone:     { icon: "zone",     tone: "info",  says: "the zone a walk starts from" },
  referral: { icon: "referral", tone: "info",  says: "sent the walk one zone further down" },
  answer:   { icon: "answer",   tone: "ok",    says: "answered the question" },
  cname:    { icon: "cname",    tone: "info",  says: "an alias, chased from here" },
  nodata:   { icon: "nodata",   tone: "warn",  says: "the name exists, the type does not" },
  nxdomain: { icon: "nxdomain", tone: "warn",  says: "the name does not exist" },
  lame:     { icon: "lame",     tone: "warn",  says: "not serving the zone it was asked about" },
  filtered: { icon: "filtered", tone: "bad",   says: "an answer somebody decided, not one served" },
  timeout:  { icon: "timeout",  tone: "bad",   says: "said nothing in time" },
  error:    { icon: "error",    tone: "bad",   says: "could not be asked" },
  skipped:  { icon: "skipped",  tone: "quiet", says: "known, never queried" },
};

export const kindOf = (kind) => KINDS[kind] ?? { icon: "unknown", tone: "quiet", says: kind };

// COOKIES are how a server can answer the DNS cookie it was sent (RFC 7873).
const COOKIES = {
  supported: { text: "cookie",           tone: "quiet", says: "answered our client cookie with one of its own" },
  absent:    { text: "no cookie",        tone: "quiet", says: "answered without a cookie, which is allowed" },
  mismatch:  { text: "cookie not ours",  tone: "bad",   says: "answered with a client cookie other than the one sent" },
  malformed: { text: "cookie malformed", tone: "warn",  says: "answered with a cookie of a length no cookie has" },
  rejected:  { text: "cookie rejected",  tone: "bad",   says: "answered BADCOOKIE even to the cookie it handed out" },
};
export const cookieOf = (state) => COOKIES[state] ?? { text: `cookie ${state}`, tone: "quiet", says: state };

const TRUST = {
  secure:        { icon: "secure",   tone: "ok" },
  insecure:      { icon: "insecure", tone: "warn" },
  bogus:         { icon: "bogus",    tone: "bad" },
  indeterminate: { icon: "unknown",  tone: "quiet" },
};
export const trustOf = (state) => TRUST[state] ?? TRUST.indeterminate;

/* ── small tools ───────────────────────────────────────────────────────── */

// took keeps a duration readable: a network answers in milliseconds, and only
// something next door answers in less.
export const took = (ms) => {
  if (ms === undefined || ms === null) return "";
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  if (ms >= 10) return `${Math.round(ms)} ms`;
  return `${ms.toFixed(ms < 1 ? 2 : 1)} ms`;
};

export const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
export const flagsOf = (flags) => Object.entries(flags ?? {}).filter(([, on]) => on).map(([f]) => f.toUpperCase());

/* ── the walk, flattened ───────────────────────────────────────────────── */

// Every hop of the trace in the order it was made, each one keeping where it
// sits so that the tree can be drawn from the same list the other views read.
export function flatten(root) {
  const hops = [];
  const visit = (step, parent, depth) => {
    if (!step) return null;
    const hop = { id: hops.length, step, parent, depth, kids: [] };
    hops.push(hop);
    parent?.kids.push(hop);
    for (const child of step.children ?? []) visit(child, hop, depth + 1);
    return hop;
  };
  visit(root, null, 0);
  return hops;
}

// asked is a hop that cost a query, which is one that put a question, as
// Step.Queried has it: the zone node, a skipped server and a note about why the
// walk stopped put none.
export const asked = (step) => Boolean(step.asked);

// aside is a hop inside work that answers another question, which the trace
// marks on the step that starts it rather than on every step below.
export const aside = (hop) => {
  for (let at = hop; at; at = at.parent) if (at.step.aside) return true;
  return false;
};

// resultOf is the hop the resolution ended on, read the way the trace itself
// defines it: the deepest one that is neither an aside nor a minimised hop.
export function resultOf(step) {
  if (!step || step.aside) return null;
  let found = !step.minimised && ["answer", "cname", "nodata", "nxdomain"].includes(step.kind) ? step : null;
  for (const child of step.children ?? []) found = resultOf(child) ?? found;
  return found;
}

export function verdictOf(hops) {
  const steps = hops.map((hop) => hop.step);
  if (steps.some((step) => step.dnssec?.state === "bogus")) return { text: "bogus", tone: "bad" };
  const result = resultOf(steps[0]);
  if (!result && steps.some((step) => step.kind === "filtered")) return { text: "filtered", tone: "bad" };
  if (!result) return { text: "no answer", tone: "warn" };
  return { text: "answered", tone: "ok" };
}

// The chain is only as good as its worst cut, which is the order the states are
// written in below.
export function chainState(hops) {
  const states = hops.map((hop) => hop.step.dnssec?.state).filter(Boolean);
  for (const state of ["bogus", "indeterminate", "insecure", "secure"]) {
    if (states.includes(state)) return state;
  }
  return "indeterminate";
}

// haystack is everything about a hop worth finding it by.
export function haystack(step) {
  return [
    step.zone, step.kind, step.server?.name, step.server?.ip, step.rcode, step.proto,
    step.server?.asn && `AS${step.server.asn.number}`, step.delegation?.zone, step.nsid,
    step.cookie && cookieOf(step.cookie).text,
    step.dnssec?.state, step.error, ...(step.notes ?? []),
    ...(step.records ?? []).flatMap((rr) => [rr.name, rr.type, rr.data]),
  ].filter(Boolean).join(" ").toLowerCase();
}

/* ── the chips a hop wears ─────────────────────────────────────────────── */

// Each chip as { text, tone, title, icon }; only the chain of trust has an icon.
export function chipsOf(step) {
  const chips = [];
  const chip = (text, tone = "quiet", title, icon) => chips.push({ text, tone, title, icon });
  if (step.kind === "referral" && step.delegation?.zone) {
    chip(`→ ${step.delegation.zone}`, "info", "the zone this referral points at");
  }
  for (const kind of ["nodata", "nxdomain", "lame", "filtered", "timeout", "error"]) {
    if (step.kind === kind) chip(kind, kindOf(kind).tone, kindOf(kind).says);
  }
  if (step.rcode && step.rcode !== "NOERROR") chip(step.rcode, "warn");
  if (step.rtt_ms) chip(took(step.rtt_ms), step.rtt_ms > 500 ? "warn" : "quiet", "round trip");
  if (step.tight) {
    chip(`${step.size_bytes} of ${step.limit_bytes} bytes`, "warn",
      "almost no room left: one more record and this answer is truncated");
  }
  if (step.server?.asn) {
    const as = step.server.asn;
    chip(`AS${as.number}`, "quiet", [as.prefix, as.country_code, as.registry].filter(Boolean).join(" · "));
  }
  const flags = flagsOf(step.flags).filter((flag) => flag !== "EDNS");
  if (flags.length) chip(flags.join(" "), "quiet", "the header bits that are set");
  if (step.subnet) chip(`ecs /${step.subnet.scope}`, "quiet", `answered for ${step.subnet.prefix}`);
  if (step.nsid) chip(`@${step.nsid}`, "quiet", "the instance behind this address, as it names itself");
  if (step.cookie) {
    const cookie = cookieOf(step.cookie);
    chip(cookie.text, cookie.tone, cookie.says);
  }
  if (step.dnssec) {
    const trust = trustOf(step.dnssec.state);
    chip(step.dnssec.state, trust.tone, step.dnssec.reason || "the chain of trust at this cut", trust.icon);
  }
  if (step.extended?.length) {
    chip("ede", step.extended.some((e) => e.withheld) ? "warn" : "quiet",
      step.extended.map((e) => [e.reason || e.code, e.text].filter(Boolean).join(": ")).join("; "));
  }
  if (step.aside) chip("aside", "quiet", "work the walk did on the way, not where it got to");
  if (step.minimised) chip("minimised", "quiet", `asked only for ${step.asked?.name ?? "part of the name"}, to find the next zone cut`);
  if (step.notes?.length) chip(step.notes.join("; "), "quiet");
  return chips;
}

/* ── the timeline ──────────────────────────────────────────────────────── */

// The same reading as Trace.Timeline: every query, and every point the walk
// gave up at, standing where the last thing before it finished. The spans are
// in the order they went out, which is not the order they joined the walk once
// --all asks the servers of a zone together.
export function timeline(hops, elapsed) {
  let now = 0;
  const spans = [];
  for (const hop of hops) {
    const { step } = hop;
    if (step.asked) {
      const start = Math.max(step.start_ms ?? 0, 0);
      const rtt = step.rtt_ms ?? 0;
      spans.push({ hop, start, rtt, aside: aside(hop) });
      now = Math.max(now, start + rtt);
    } else if (step.kind === "error") {
      spans.push({ hop, start: now, rtt: 0, aside: aside(hop), stop: true });
    }
  }
  spans.sort((a, b) => a.start - b.start);
  const total = Math.max(elapsed ?? 0, ...spans.map((span) => span.start + span.rtt), 0.001);
  return { spans, total };
}

// ticks are round moments along a timeline, few enough to read.
export function ticks(total) {
  // A hand-written file can carry a time no walk takes; it gets no scale.
  if (!Number.isFinite(total)) return [0];
  let step = 0.001;
  for (let unit = 0.001; ; unit *= 10) {
    const fit = [1, 2, 5].map((n) => n * unit).find((n) => total / n < 5);
    if (fit) { step = fit; break; }
  }
  const marks = [];
  for (let ms = 0; ms <= total + 1e-9; ms += step) marks.push(Math.round(ms * 1000) / 1000);
  return marks;
}
