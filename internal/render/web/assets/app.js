// The page dnstree serves. It draws one finished walk and never works anything
// out about the DNS for itself: every line here is something the trace already
// records, so the page and the tree the terminal prints cannot come to
// disagree.

const SVG = "http://www.w3.org/2000/svg";

/* ── the vocabulary of a trace ─────────────────────────────────────────── */

// What each kind of hop is called, drawn with, and coloured by.
const KINDS = {
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
const kindOf = (kind) => KINDS[kind] ?? { icon: "unknown", tone: "quiet", says: kind };

const TRUST = {
  secure:        { icon: "secure",   tone: "ok" },
  insecure:      { icon: "insecure", tone: "warn" },
  bogus:         { icon: "bogus",    tone: "bad" },
  indeterminate: { icon: "unknown",  tone: "quiet" },
};
const trustOf = (state) => TRUST[state] ?? TRUST.indeterminate;

/* ── small tools ───────────────────────────────────────────────────────── */

// What there is none of is left out rather than written as the word for nothing.
// A view is filled, which replaces what was there; a node is built, which adds.
const kept = (kids) => kids.filter(Boolean);
const fill = (node, ...kids) => node.replaceChildren(...kept(kids));

const el = (tag, props = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "class") node.className = value;
    else if (name === "text") node.textContent = value;
    else if (name.startsWith("on")) node.addEventListener(name.slice(2), value);
    else node.setAttribute(name, value === true ? "" : value);
  }
  node.append(...kept(kids));
  return node;
};

const icon = (name, cls = "glyph") => {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", cls);
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(SVG, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
};

const chip = (text, tone = "quiet", title) =>
  el("span", { class: `chip tone-${tone}`, title, text });

// took keeps a duration readable: a network answers in milliseconds, and only
// something next door answers in less.
const took = (ms) => {
  if (ms === undefined || ms === null) return "";
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  if (ms >= 10) return `${Math.round(ms)} ms`;
  return `${ms.toFixed(ms < 1 ? 2 : 1)} ms`;
};

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const flagsOf = (flags) => Object.entries(flags ?? {}).filter(([, on]) => on).map(([f]) => f.toUpperCase());

/* ── the walk, flattened ───────────────────────────────────────────────── */

// Every hop of the trace in the order it was made, each one keeping where it
// sits so that the tree can be drawn from the same list the other views read.
function flatten(root) {
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

// asked is a hop that cost a query. The synthetic zone node never was one, and
// a skipped server never was asked.
const asked = (step) => step.kind !== "zone" && step.kind !== "skipped";

// resultOf is the hop the resolution ended on, read the way the trace itself
// defines it: the deepest one that is not an aside.
function resultOf(step) {
  if (!step || step.aside) return null;
  let found = ["answer", "cname", "nodata", "nxdomain"].includes(step.kind) ? step : null;
  for (const child of step.children ?? []) found = resultOf(child) ?? found;
  return found;
}

function verdictOf(hops) {
  const steps = hops.map((hop) => hop.step);
  if (steps.some((step) => step.dnssec?.state === "bogus")) return { text: "bogus", tone: "bad" };
  const result = resultOf(steps[0]);
  if (!result && steps.some((step) => step.kind === "filtered")) return { text: "filtered", tone: "bad" };
  if (!result) return { text: "no answer", tone: "warn" };
  return { text: "answered", tone: "ok" };
}

// haystack is everything about a hop worth finding it by.
function haystack(step) {
  return [
    step.zone, step.kind, step.server?.name, step.server?.ip, step.rcode, step.proto,
    step.server?.asn && `AS${step.server.asn.number}`, step.delegation?.zone, step.nsid,
    step.dnssec?.state, step.error, ...(step.notes ?? []),
    ...(step.records ?? []).flatMap((rr) => [rr.name, rr.type, rr.data]),
  ].filter(Boolean).join(" ").toLowerCase();
}

/* ── the chips a hop wears ─────────────────────────────────────────────── */

function chipsFor(step) {
  const chips = [];
  if (step.kind === "referral" && step.delegation?.zone) {
    chips.push(chip(`→ ${step.delegation.zone}`, "info", "the zone this referral points at"));
  }
  for (const kind of ["nodata", "nxdomain", "lame", "filtered", "timeout", "error"]) {
    if (step.kind === kind) chips.push(chip(kind, kindOf(kind).tone, kindOf(kind).says));
  }
  if (step.rcode && step.rcode !== "NOERROR") chips.push(chip(step.rcode, "warn"));
  if (step.rtt_ms) chips.push(chip(took(step.rtt_ms), step.rtt_ms > 500 ? "warn" : "quiet", "round trip"));
  if (step.server?.asn) {
    const as = step.server.asn;
    chips.push(chip(`AS${as.number}`, "quiet", [as.prefix, as.country_code, as.registry].filter(Boolean).join(" · ")));
  }
  const flags = flagsOf(step.flags).filter((flag) => flag !== "EDNS");
  if (flags.length) chips.push(chip(flags.join(" "), "quiet", "the header bits that are set"));
  if (step.subnet) chips.push(chip(`ecs /${step.subnet.scope}`, "quiet", `answered for ${step.subnet.prefix}`));
  if (step.nsid) chips.push(chip(`@${step.nsid}`, "quiet", "the instance behind this address, as it names itself"));
  if (step.dnssec) {
    const trust = trustOf(step.dnssec.state);
    chips.push(el("span", { class: `chip tone-${trust.tone}`, title: step.dnssec.reason || "the chain of trust at this cut" },
      icon(trust.icon), step.dnssec.state));
  }
  if (step.extended?.length) {
    chips.push(chip("ede", step.extended.some((e) => e.withheld) ? "warn" : "quiet",
      step.extended.map((e) => [e.reason || e.code, e.text].filter(Boolean).join(": ")).join("; ")));
  }
  if (step.aside) chips.push(chip("aside", "quiet", "work the walk did on the way, not where it got to"));
  if (step.notes?.length) chips.push(chip(step.notes.join("; "), "quiet"));
  return chips;
}

/* ── the tree ──────────────────────────────────────────────────────────── */

class DnsTree extends HTMLElement {
  #rows = [];

  set hops(hops) {
    this.#rows = [];
    const list = el("ol", { class: "tree", role: "tree", "aria-label": "the walk" },
      this.#draw(hops[0]));
    fill(this, list);
    this.#select(this.#rows[0], { quiet: true });
    this.addEventListener("keydown", (event) => this.handleKey(event));
  }

  #draw(hop) {
    const { step } = hop;
    const node = document.getElementById("tpl-hop").content.firstElementChild.cloneNode(true);
    const row = node.querySelector(".row");
    const kind = kindOf(step.kind);

    node.classList.add(`tone-${kind.tone}`);
    node.classList.toggle("aside", Boolean(step.aside));
    node.dataset.id = hop.id;
    node.setAttribute("aria-level", hop.depth + 1);
    row.querySelector(".mark use").setAttribute("href", `#i-${kind.icon}`);
    row.querySelector(".ns").textContent = step.server?.name || step.zone || "";
    row.querySelector(".ip").textContent = step.server?.ip ?? "";
    row.querySelector(".chips").append(...chipsFor(step));
    row.title = kind.says;

    row.addEventListener("click", () => this.#select(hop));
    node.querySelector(".twist").addEventListener("click", (event) => {
      event.stopPropagation();
      this.#fold(hop, !node.hasAttribute("data-folded"));
    });

    hop.node = node;
    hop.row = row;
    this.#rows.push(hop); // in the order the walk made them, which is the order the keys move in

    const kids = node.querySelector(".kids");
    for (const record of step.records ?? []) kids.append(this.#record(record, hop));
    for (const child of hop.kids) kids.append(this.#draw(child));
    node.setAttribute("aria-expanded", kids.childElementCount ? "true" : "false");
    return node;
  }

  #record(record, hop) {
    const node = document.getElementById("tpl-record").content.firstElementChild.cloneNode(true);
    node.querySelector(".rr-name").textContent = record.name;
    node.querySelector(".rr-type").textContent = record.type;
    node.querySelector(".rr-data").textContent = record.data;
    node.querySelector(".chips").append(...[
      chip(`ttl ${record.ttl}`, "quiet"),
      // ECH is the one parameter worth acting on: it hides the name a client is
      // about to ask for, and only if this record arrived as the zone wrote it.
      record.service?.ech ? chip("ech", "ok", "this service publishes an encrypted client hello") : null,
    ].filter(Boolean));
    node.querySelector(".row").addEventListener("click", () => this.#select(hop));
    return node;
  }

  #fold(hop, folded) {
    hop.node.toggleAttribute("data-folded", folded);
    hop.node.setAttribute("aria-expanded", String(!folded));
  }

  #select(hop, { quiet = false } = {}) {
    if (!hop) return;
    for (const other of this.#rows) {
      other.node.removeAttribute("aria-selected");
      other.node.tabIndex = -1;
    }
    hop.node.setAttribute("aria-selected", "true");
    hop.node.tabIndex = 0;
    this.selected = hop;
    if (!quiet) hop.node.focus({ preventScroll: true });
    this.dispatchEvent(new CustomEvent("hop", { detail: hop, bubbles: true }));
  }

  // The keys a tree is walked with, as any other tree is walked. It is public
  // because the keys work before anything in the tree has been clicked, and
  // then the page hands the event over rather than the tree catching it.
  handleKey(event) {
    const shown = this.#rows.filter((hop) => hop.node.checkVisibility());
    const at = shown.indexOf(this.selected);
    const moves = {
      ArrowDown: () => this.#select(shown[Math.min(at + 1, shown.length - 1)]),
      ArrowUp: () => this.#select(shown[Math.max(at - 1, 0)]),
      Home: () => this.#select(shown[0]),
      End: () => this.#select(shown.at(-1)),
      ArrowRight: () => {
        if (this.selected?.node.hasAttribute("data-folded")) this.#fold(this.selected, false);
        else if (this.selected?.kids.length) this.#select(shown[at + 1]);
      },
      ArrowLeft: () => {
        if (this.selected?.kids.length && !this.selected.node.hasAttribute("data-folded")) {
          this.#fold(this.selected, true);
        } else if (this.selected?.parent) {
          this.#select(this.selected.parent);
        }
      },
    };
    const move = moves[event.key];
    if (!move) return;
    event.preventDefault();
    move();
    this.selected?.node.scrollIntoView({ block: "nearest" });
  }

  // A hop stays when it matches, and so does every hop on the way down to one
  // that does: a match nobody can see is a match hidden behind its parents.
  filter(query) {
    let hits = 0;
    const keep = (hop) => {
      const here = !query || hop.text.includes(query);
      const below = hop.kids.map(keep).some(Boolean);
      const shown = here || below;
      hop.node.dataset.hit = shown ? "1" : "0";
      if (here) hits++;
      if (query && below) this.#fold(hop, false);
      return shown;
    };
    keep(this.#rows.find((hop) => hop.depth === 0));
    return hits;
  }
}

/* ── how long each hop took ────────────────────────────────────────────── */

class DnsTiming extends HTMLElement {
  set hops(hops) {
    const made = hops.filter((hop) => asked(hop.step));
    const slowest = Math.max(...made.map((hop) => hop.step.rtt_ms ?? 0), 0.001);

    fill(this,
      made.length && el("p", { class: "group-title" }, "round trips",
        el("span", { text: "what each server took to answer. hops the walk made at the same time are drawn one under the other." })),
      made.length
        ? el("div", { class: "bars" }, ...made.map((hop) => this.#bar(hop, slowest)))
        : el("p", { class: "empty-note", text: "no server was asked" }),
    );
  }

  #bar(hop, slowest) {
    const { step } = hop;
    const width = `${Math.max(1.5, ((step.rtt_ms ?? 0) / slowest) * 100)}%`;
    const row = el("div", { class: `bar-row tone-${kindOf(step.kind).tone}` },
      el("span", { class: "label", text: step.server?.name || step.server?.ip || step.zone, title: step.zone }),
      el("div", { class: "track" }, el("div", { class: "fill", style: `--fill:${width}` })),
      el("span", { class: "took", text: took(step.rtt_ms) || "—" }),
    );
    row.dataset.text = hop.text;
    row.addEventListener("click", () => this.dispatchEvent(new CustomEvent("hop", { detail: hop, bubbles: true })));
    return row;
  }

  filter(query) {
    let hits = 0;
    for (const row of this.querySelectorAll(".bar-row")) {
      const shown = !query || row.dataset.text.includes(query);
      row.hidden = !shown;
      if (shown) hits++;
    }
    return hits;
  }
}

/* ── who answered, and from where ──────────────────────────────────────── */

class DnsServers extends HTMLElement {
  set hops(hops) {
    const known = hops.filter((hop) => hop.step.server?.ip);
    const byAddress = Object.groupBy(known, (hop) => hop.step.server.ip);
    const servers = Object.entries(byAddress).map(([ip, at]) => ({
      ip,
      asn: at.find((hop) => hop.step.server.asn)?.step.server.asn,
      names: [...new Set(at.map((hop) => hop.step.server.name).filter(Boolean))],
      zones: [...new Set(at.map((hop) => hop.step.zone))],
      hops: at,
      queries: at.filter((hop) => asked(hop.step)).length,
      rtts: at.map((hop) => hop.step.rtt_ms).filter(Boolean),
    }));

    const byOrigin = Object.groupBy(servers, (server) => (server.asn ? `AS${server.asn.number}` : "no origin AS"));
    const groups = Object.entries(byOrigin).toSorted(([a], [b]) => a.localeCompare(b));

    fill(this, ...groups.flatMap(([origin, members]) => {
      const as = members.find((server) => server.asn)?.asn;
      return [
        el("h2", { class: "group-title" }, origin,
          el("span", { text: [as?.prefix, as?.country_code, as?.registry, as?.allocated].filter(Boolean).join(" · ") || "the lookups found none" })),
        el("div", { class: "cards" }, ...members.map((server) => this.#card(server))),
      ];
    }));
    if (!servers.length) fill(this, el("p", { class: "empty-note", text: "no server answered" }));
  }

  #card(server) {
    const fastest = server.rtts.length ? Math.min(...server.rtts) : null;
    const card = el("div", { class: "card" },
      el("h3", { text: server.names[0] ?? server.ip }),
      el("p", { class: "sub", text: server.ip }),
      el("div", { class: "chips" }, ...[
        server.queries
          ? chip(plural(server.queries, "query", "queries"), "quiet")
          : chip("never asked", "quiet", "the walk knew of this server and had no need of it"),
        fastest === null ? null : chip(`fastest ${took(fastest)}`, "quiet"),
        ...server.zones.map((zone) => chip(zone, "info", "a zone it was asked about")),
      ].filter(Boolean)),
    );
    card.dataset.text = server.hops.map((hop) => hop.text).join(" ");
    card.addEventListener("click", () =>
      this.dispatchEvent(new CustomEvent("hop", { detail: server.hops[0], bubbles: true })));
    return card;
  }

  filter(query) {
    let hits = 0;
    for (const card of this.querySelectorAll(".card")) {
      const shown = !query || card.dataset.text.includes(query);
      card.hidden = !shown;
      if (shown) hits++;
    }
    for (const group of this.querySelectorAll(".group-title")) {
      group.hidden = !group.nextElementSibling.querySelector(".card:not([hidden])");
    }
    return hits;
  }
}

/* ── the chain of trust ────────────────────────────────────────────────── */

class DnsTrust extends HTMLElement {
  set hops(hops) {
    const cuts = hops.filter((hop) => hop.step.dnssec);
    if (!cuts.length) {
      fill(this, el("p", { class: "empty-note" },
        "this walk followed no chain of trust. ",
        el("code", { class: "mono", text: "--dnssec" }),
        " asks for the signatures and checks them cut by cut."));
      return;
    }

    const whole = cuts.every((hop) => hop.step.dnssec.state === "secure");
    fill(this,
      el("p", { class: "group-title" }, "chain of trust",
        el("span", { text: whole ? "signed the whole way down" : "read it from the top: a cut that breaks decides everything under it" })),
      el("div", { class: `chain ${whole ? "chain-secure tone-ok" : ""}` }, ...cuts.map((hop) => this.#cut(hop))),
    );
  }

  #cut(hop) {
    const { step } = hop;
    const trust = trustOf(step.dnssec.state);
    // A cut is judged from above, so a referral carries the verdict of the zone
    // it points at rather than the zone that gave it.
    const zone = step.delegation?.zone ?? step.zone;
    const how = [step.dnssec.algorithm, step.dnssec.digest].filter(Boolean).join(" / ");
    const said = [
      step.dnssec.reason,
      how && `signed with ${how}`,
      step.dnssec.key_tags?.length && `key ${step.dnssec.key_tags.join(", ")}`,
      step.server?.name && `as ${step.server.name} says`,
    ].filter(Boolean).join(" · ");

    const cut = el("div", { class: `cut tone-${trust.tone}` },
      el("span", { class: "mark" }, icon(trust.icon)),
      el("h3", { text: `${zone} — ${step.dnssec.state}` }),
      el("p", { text: said || "nothing more was recorded about this cut" }),
    );
    cut.dataset.text = hop.text;
    cut.addEventListener("click", () => this.dispatchEvent(new CustomEvent("hop", { detail: hop, bubbles: true })));
    return cut;
  }

  filter(query) {
    let hits = 0;
    for (const cut of this.querySelectorAll(".cut")) {
      const shown = !query || cut.dataset.text.includes(query);
      cut.hidden = !shown;
      if (shown) hits++;
    }
    return hits;
  }
}

/* ── one hop, in full ──────────────────────────────────────────────────── */

class DnsInspector extends HTMLElement {
  set hop(hop) {
    const { step } = hop;
    const kind = kindOf(step.kind);

    fill(this,
      el("div", { class: "panel-head" },
        el("span", { class: `mark tone-${kind.tone}` }, icon(kind.icon)),
        el("div", {},
          el("h2", { text: step.server?.name || step.server?.ip || step.zone }),
          el("span", { class: "zone", text: `${step.kind} · ${step.zone}` })),
      ),
      el("div", { class: "panel-body" },
        this.#facts(step),
        this.#records(step),
        this.#delegation(step),
        this.#trust(step),
        this.#extended(step),
        this.#notes(step),
      ),
    );
  }

  #facts(step) {
    const as = step.server?.asn;
    const facts = [
      ["server", [step.server?.ip, step.server?.port && `:${step.server.port}`].filter(Boolean).join("")],
      ["over", step.proto],
      ["took", took(step.rtt_ms)],
      ["rcode", step.rcode],
      ["flags", flagsOf(step.flags).join(" ")],
      ["subnet", step.subnet && `${step.subnet.prefix} scope /${step.subnet.scope}`],
      ["instance", step.nsid],
      ["origin", as && `AS${as.number} ${as.prefix ?? ""}`.trim()],
      ["registry", as && [as.country_code, as.registry, as.allocated].filter(Boolean).join(" · ")],
      ["error", step.error],
    ].filter(([, value]) => value);

    return el("dl", { class: "facts" },
      ...facts.flatMap(([name, value]) => [el("dt", { text: name }), el("dd", { text: value })]));
  }

  #block(title, count, body, open = false) {
    return el("details", { class: "block", open },
      el("summary", {}, title, el("span", { class: "count", text: String(count) })),
      body);
  }

  #records(step) {
    if (!step.records?.length) return null;
    return this.#block("records", step.records.length,
      el("ul", { class: "rows" }, ...step.records.map((rr) => el("li", {},
        el("span", { class: "k", text: rr.type }),
        el("span", { text: rr.data }),
        el("span", { class: "t", text: `${rr.ttl}s` }),
      ))), true);
  }

  #delegation(step) {
    const delegation = step.delegation;
    if (!delegation) return null;

    const rows = (delegation.ns ?? []).map((name) => {
      const glue = delegation.glue?.[name];
      const note = glue ? glue.join(", ")
        : delegation.glueless?.includes(name) ? "no glue, and inside the zone it serves"
        : delegation.out_of_bailiwick?.includes(name) ? "outside the zone, looked up on its own"
        : "";
      return el("li", {}, el("span", { class: "k", text: "NS" }), el("span", { text: name }),
        note ? el("span", { class: "t", text: note }) : null);
    });

    return this.#block(`delegation → ${delegation.zone}`, rows.length,
      el("ul", { class: "rows" }, ...rows,
        el("li", {}, el("span", { class: "k", text: "DS" }),
          el("span", { text: delegation.ds_present ? "the parent signed this delegation" : "the parent signed nothing here" }))));
  }

  #trust(step) {
    if (!step.dnssec) return null;
    const rows = [
      ["state", step.dnssec.state],
      ["why", step.dnssec.reason],
      ["algorithm", step.dnssec.algorithm],
      ["digest", step.dnssec.digest],
      ["keys", step.dnssec.key_tags?.join(", ")],
    ].filter(([, value]) => value);

    return this.#block("chain of trust", step.dnssec.state,
      el("ul", { class: "rows" }, ...rows.map(([name, value]) =>
        el("li", {}, el("span", { class: "k", text: name }), el("span", { text: value })))), true);
  }

  #extended(step) {
    if (!step.extended?.length) return null;
    return this.#block("what the server said", step.extended.length,
      el("ul", { class: "rows" }, ...step.extended.map((ede) => el("li", {},
        el("span", { class: "k", text: String(ede.code) }),
        el("span", { text: [ede.reason, ede.text].filter(Boolean).join(": ") }),
        ede.withheld ? el("span", { class: "t", text: "withheld" }) : null,
      ))), true);
  }

  #notes(step) {
    if (!step.notes?.length) return null;
    return this.#block("what it took", step.notes.length,
      el("ul", { class: "rows" }, ...step.notes.map((note) => el("li", {}, el("span", { text: note })))));
  }
}

/* ── the sentences under it all ────────────────────────────────────────── */

class DnsFindings extends HTMLElement {
  set findings(findings) {
    if (!findings?.length) return;
    fill(this, el("div", { class: "findings" }, ...findings.map((finding) =>
      el("p", { class: `finding level-${finding.level} tone-${finding.level === "fault" ? "bad" : finding.level === "warn" ? "warn" : "quiet"}` },
        el("span", { class: "topic", text: finding.topic }),
        el("span", { text: finding.text })))));
  }
}

customElements.define("dns-tree", DnsTree);
customElements.define("dns-timing", DnsTiming);
customElements.define("dns-servers", DnsServers);
customElements.define("dns-trust", DnsTrust);
customElements.define("dns-inspector", DnsInspector);
customElements.define("dns-findings", DnsFindings);

/* ── the page itself ───────────────────────────────────────────────────── */

const page = await fetch("page.json", { cache: "no-store" }).then((answer) => answer.json());
const walk = page.trace;
const hops = flatten(walk.root);
for (const hop of hops) hop.text = haystack(hop.step);

document.title = `${walk.question.name} ${walk.question.type} · dnstree`;
document.getElementById("q-name").textContent = walk.question.name;
document.getElementById("q-type").textContent = walk.question.type;
document.getElementById("q-class").textContent = walk.question.class;

const decided = verdictOf(hops);
const verdict = document.getElementById("verdict");
verdict.textContent = decided.text;
verdict.classList.add(`tone-${decided.tone}`);

// What the walk cost, counted the way the summary under the terminal tree
// counts it: one query per hop that was made, and the servers those went to.
const queries = hops.filter((hop) => asked(hop.step)).length;
const servers = new Set(
  hops.filter((hop) => asked(hop.step)).map((hop) => hop.step.server?.ip).filter(Boolean),
).size;
// One resolver reads as one; several read as how many of them disagreed, since
// the reason to ask several is whether they agree rather than what each took.
const resolvers = walk.resolvers ?? [];
const differing = resolvers.filter((r) => r.match === "differs").length;
document.getElementById("stats").append(...[
  el("span", { class: "stat" }, "walked in ", el("b", { text: took(walk.elapsed_ms) })),
  el("span", { class: "stat" }, el("b", { text: String(queries) }), " queries"),
  el("span", { class: "stat" }, el("b", { text: String(servers) }), " servers"),
  resolvers.length === 1
    ? el("span", { class: `stat ${differing ? "is-tone tone-warn" : ""}` },
      "a resolver in ", el("b", { text: took(resolvers[0].elapsed_ms) }),
      differing ? " · answers differently" : "")
    : resolvers.length
      ? el("span", { class: `stat ${differing ? "is-tone tone-warn" : ""}` },
        el("b", { text: String(resolvers.length) }), " resolvers",
        differing ? ` · ${differing} answer differently` : " · all agree")
      : null,
  hops.some((hop) => hop.step.dnssec)
    ? el("span", { class: `stat is-tone tone-${trustOf(chainState(hops)).tone}` }, el("b", { text: chainState(hops) }), " chain")
    : null,
].filter(Boolean));

// The chain is only as good as its worst cut, which is the order the states are
// written in below.
function chainState(hops) {
  const states = hops.map((hop) => hop.step.dnssec?.state).filter(Boolean);
  for (const state of ["bogus", "indeterminate", "insecure", "secure"]) {
    if (states.includes(state)) return state;
  }
  return "indeterminate";
}

const views = {
  tree: document.getElementById("view-tree"),
  timing: document.getElementById("view-timing"),
  servers: document.getElementById("view-servers"),
  trust: document.getElementById("view-trust"),
};
for (const view of Object.values(views)) view.hops = hops;
document.getElementById("findings").findings = page.findings;
document.getElementById("inspector").hop = hops[0];

document.addEventListener("hop", (event) => {
  document.getElementById("inspector").hop = event.detail;
});

document.getElementById("built").textContent =
  `dnstree ${page.page.version} · walked ${new Date(page.page.generated).toLocaleString()}`;
if (walk.warnings?.length) {
  document.getElementById("warnings").append(
    el("span", { class: "sep", text: "·" }),
    el("span", { class: "warn", text: walk.warnings.join(" · ") }),
  );
}

document.getElementById("legend").append(...Object.entries(KINDS).map(([name, kind]) =>
  el("li", { class: `tone-${kind.tone}` }, el("span", { class: "mark" }, icon(kind.icon)), name)));

/* ── switching, finding, folding ───────────────────────────────────────── */

let current = "tree";
const show = (name, { keep = false } = {}) => {
  // The name comes out of the address bar, so it is matched against the keys the
  // page actually has: anything inherited, "__proto__" above all, is not a view.
  if (!Object.hasOwn(views, name) || name === current) return;
  const swap = () => {
    for (const [key, view] of Object.entries(views)) view.hidden = key !== name;
    for (const tab of document.querySelectorAll('[role="tab"]')) {
      tab.setAttribute("aria-selected", String(tab.dataset.view === name));
    }
    current = name;
    find(search.value);
    // The view is in the address, so a window kept open on the timing of a walk
    // opens on it again.
    if (!keep) history.replaceState(null, "", `#${name}`);
  };
  document.startViewTransition ? document.startViewTransition(swap) : swap();
};
for (const tab of document.querySelectorAll('[role="tab"]')) {
  tab.addEventListener("click", () => show(tab.dataset.view));
}
addEventListener("hashchange", () => show(location.hash.slice(1), { keep: true }));

const search = document.getElementById("find");
const empty = document.getElementById("empty");

// The matches are painted over the text rather than into it, so nothing here
// touches the words the trace recorded.
function highlight(query) {
  if (!CSS.highlights) return;
  CSS.highlights.delete("found");
  if (!query) return;

  const ranges = [];
  const walker = document.createTreeWalker(views[current], NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode()) {
    const text = node.textContent.toLowerCase();
    for (let at = text.indexOf(query); at >= 0; at = text.indexOf(query, at + query.length)) {
      const range = new Range();
      range.setStart(node, at);
      range.setEnd(node, at + query.length);
      ranges.push(range);
    }
  }
  CSS.highlights.set("found", new Highlight(...ranges));
}

function find(text) {
  const query = text.trim().toLowerCase();
  const hits = views[current].filter(query);
  empty.hidden = Boolean(hits) || !query;
  empty.querySelector("b").textContent = text;
  views[current].hidden = !hits && Boolean(query);
  highlight(query);
}
search.addEventListener("input", () => find(search.value));

const asides = document.getElementById("asides");
const records = document.getElementById("records");
const toggle = () => {
  views.tree.classList.toggle("no-asides", !asides.checked);
  views.tree.classList.toggle("no-records", !records.checked);
};
asides.addEventListener("change", toggle);
records.addEventListener("change", toggle);

const theme = document.getElementById("theme");
const themes = ["auto", "light", "dark"];
theme.addEventListener("click", () => {
  const next = themes[(themes.indexOf(document.documentElement.dataset.theme) + 1) % themes.length];
  document.documentElement.dataset.theme = next;
  theme.title = `theme: ${next}`;
  try { localStorage.setItem("dnstree-theme", next); } catch { /* a browser that keeps nothing still draws */ }
});
try {
  const kept = localStorage.getItem("dnstree-theme");
  if (kept) document.documentElement.dataset.theme = kept;
} catch { /* likewise */ }

const WALKING = ["ArrowDown", "ArrowUp", "ArrowLeft", "ArrowRight", "Home", "End"];

show(location.hash.slice(1), { keep: true });

document.addEventListener("keydown", (event) => {
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const typing = event.target.matches("input, textarea");

  if (event.key === "Escape" && typing) {
    search.value = "";
    find("");
    search.blur();
    return;
  }
  if (typing) return;

  // The tree catches these itself once it holds the focus; until then the page
  // passes them on, so the keys work on a page nobody has clicked yet.
  if (WALKING.includes(event.key) && current === "tree" && !views.tree.contains(event.target)) {
    views.tree.handleKey(event);
    return;
  }
  if (event.key === "/") { event.preventDefault(); search.focus(); return; }
  if (event.key === "?") { document.getElementById("help").togglePopover(); return; }
  if (event.key === "a") { asides.checked = !asides.checked; toggle(); return; }
  if (event.key === "r") { records.checked = !records.checked; toggle(); return; }
  const at = Number(event.key);
  if (at >= 1 && at <= 4) show(Object.keys(views)[at - 1]);
});
