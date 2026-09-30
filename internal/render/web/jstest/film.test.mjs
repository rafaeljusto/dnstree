import { test } from "node:test";
import assert from "node:assert/strict";

import { formatFor, framed, filmLength, filmName } from "../assets/scene/film.js";

test("a film is made in the best format the browser can record", () => {
  const cases = {
    "vp9 when there is everything": [() => true, "video/webm;codecs=vp9"],
    "plain webm when that is all": [(type) => type === "video/webm", "video/webm"],
    "mp4 on a browser that only records that": [(type) => type === "video/mp4", "video/mp4"],
  };
  for (const [name, [supported, want]] of Object.entries(cases)) assert.equal(formatFor(supported).type, want, name);
  assert.equal(formatFor(() => false), null, "nothing, when it can record nothing");
  assert.equal(formatFor((type) => type === "video/mp4").ext, "mp4");
});

test("a frame is at most 1920 on its long side, in even numbers", () => {
  const cases = {
    "a small window is kept as it is": [[1280, 720], [1280, 720]],
    "a retina canvas is brought down": [[2800, 1700], [1920, 1166]],
    "a tall one by its height": [[1000, 3000], [640, 1920]],
    "odd sizes are made even": [[1001, 701], [1002, 702]],
    "a canvas of nothing is still a frame": [[0, 0], [2, 2]],
  };
  for (const [name, [[w, h], want]] of Object.entries(cases)) {
    const got = framed(w, h);
    assert.deepEqual(got, want, name);
    assert.ok(got.every((n) => n % 2 === 0), name);
  }
});

test("a film runs through the replay and a little after, within a length worth sharing", () => {
  assert.equal(filmLength(1), 6);
  assert.equal(filmLength(8), 11);
  assert.equal(filmLength(60), 20);
});

test("a film is named after what was looked up", () => {
  const webm = { ext: "webm" };
  const cases = {
    "a name and its type": [{ name: "www.example.com.", type: "A" }, "dnstree-www.example.com-A.webm"],
    "the root": [{ name: ".", type: "NS" }, "dnstree-NS.webm"],
    "an escaped name keeps nothing a file system chokes on": [
      { name: "we\\ird\\032name/..\\.example.", type: "TXT" }, "dnstree-we-ird-032name-..-.example-TXT.webm",
    ],
    "a name typed in another script, as its punycode": [{ name: "xn--caf-dma.example.", type: "AAAA" }, "dnstree-xn--caf-dma.example-AAAA.webm"],
  };
  for (const [name, [question, want]] of Object.entries(cases)) assert.equal(filmName(question, webm), want, name);
  assert.equal(filmName({ name: "a.", type: "A" }, { ext: "mp4" }), "dnstree-a-A.mp4");
});
