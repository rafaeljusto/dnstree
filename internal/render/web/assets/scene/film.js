// What a film of the scene is made as: the format this browser can record,
// the size of the frame, how long it runs and what the file is called.
// Recording itself needs the page; these are the choices around it.

// Most preferred first. WebM is what Chrome and Firefox record; Safari only
// records MP4.
const FORMATS = [
  { type: "video/webm;codecs=vp9", ext: "webm" },
  { type: "video/webm;codecs=vp8", ext: "webm" },
  { type: "video/webm", ext: "webm" },
  { type: "video/mp4", ext: "mp4" },
];

// The first format the browser says it can record, or null when it can
// record none of them.
export const formatFor = (supported) => FORMATS.find((format) => supported(format.type)) ?? null;

// A frame no longer than 1920 on its long side, in even numbers: encoders
// refuse odd ones, and a retina canvas is more than a film needs.
export function framed(width, height) {
  const k = Math.min(1, 1920 / Math.max(width, height, 1));
  const even = (n) => Math.max(2, 2 * Math.round((n * k) / 2));
  return [even(width), even(height)];
}

// The replay and a few seconds at the end to look at, within a length worth
// sharing.
export const filmLength = (replayEnd) => Math.min(20, Math.max(6, replayEnd + 3));

// A file name that says what was looked up, in characters every file system
// takes. The name comes escaped from the trace, so anything past letters,
// digits, dots and hyphens is folded into one hyphen.
export function filmName(question, format) {
  const safe = (text) => text.replace(/[^A-Za-z0-9.-]+/g, "-").replace(/^[.-]+|[.-]+$/g, "");
  const parts = ["dnstree", safe(question.name), safe(question.type)].filter(Boolean);
  return `${parts.join("-")}.${format.ext}`;
}
