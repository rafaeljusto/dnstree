// The walks the tests read. The golden --format json writes is a real trace,
// so the pages are checked against the shape the resolver actually records;
// the rest are built by hand for what that one walk does not have.

import { readFileSync } from "node:fs";

// A fresh copy each time: the functions under test write onto the hops.
export const golden = () =>
  JSON.parse(readFileSync(new URL("../../jsonout/testdata/resolution.golden", import.meta.url), "utf8"));

export const zone = (...children) => ({ zone: ".", kind: "zone", children });

let next = 1;
export const step = (kind, fields = {}, ...children) => ({
  zone: "example.",
  kind,
  server: { name: `ns${next}.example.`, ip: `192.0.2.${next++ % 250}`, port: 53 },
  rtt_ms: 10,
  ...fields,
  ...(children.length ? { children } : {}),
});

// A delegation chain as deep as asked, ending in an answer.
export const chain = (depth, fields = {}) => {
  let at = step("answer", { asked: { name: "www.example.", type: "A" }, ...fields });
  for (let i = 1; i < depth; i++) at = step("referral", { asked: { name: "www.example.", type: "A" }, ...fields }, at);
  return zone(at);
};
