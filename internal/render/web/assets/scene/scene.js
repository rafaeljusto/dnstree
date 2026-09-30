// The scene --format web-3d serves: the same walk --format web draws, turned
// into something to fly around. It is WebGL2 and Web Audio with nothing
// fetched, and it works nothing out about the DNS for itself: every shape,
// colour and sound stands for something the trace already records.

import {
  TONES, KINDS, kindOf, trustTone, took, clamp, flatten, asked, resultOf, verdictOf, chainState,
  layout, drift, schedule, titleOf, subtitleOf, factsOf, declutter, stepFrom, leaks,
  trailOf, rideAt, behind, around, landingOf,
} from "./walk.js";
import { STRIDE, nodesOf, wiresOf } from "./pack.js";
import { formatFor, framed, filmLength, filmName } from "./film.js";
import { SHAPES, sub, add, scale, cross, norm, mix, perspective, lookAt, multiply, project } from "./space.js";

const toCss = ([r, g, b]) => `rgb(${Math.round(r * 255)} ${Math.round(g * 255)} ${Math.round(b * 255)})`;
for (const [name, rgb] of Object.entries(TONES)) {
  document.documentElement.style.setProperty(`--tone-${name}`, toCss(rgb));
}

/* ── small tools ───────────────────────────────────────────────────────── */

const $ = (id) => document.getElementById(id);

const el = (tag, props = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "class") node.className = value;
    else if (name === "text") node.textContent = value;
    else if (name === "style") node.style.cssText = value;
    else node.setAttribute(name, value);
  }
  node.append(...kids.filter((kid) => kid !== null && kid !== undefined && kid !== false));
  return node;
};

const reduced = matchMedia("(prefers-reduced-motion: reduce)");

/* ── shaders ───────────────────────────────────────────────────────────── */

const COMMON = `#version 300 es
precision highp float;
uniform mat4 uViewProj;
uniform float uTime;
uniform float uReplay;
uniform float uMotion;
uniform float uPixels;
uniform float uMaxPoint;
uniform float uDpr;
vec3 drift(vec3 p, float phase) {
  if (phase < 0.0) return p;
  return p + uMotion * vec3(cos(uTime * 0.53 + phase * 1.7) * 0.06, sin(uTime * 0.9 + phase) * 0.16, sin(uTime * 0.61 + phase * 2.3) * 0.06);
}
float grow(float at) {
  float k = clamp((uReplay - at) / 0.55, 0.0, 1.0);
  if (k <= 0.0) return 0.0;
  // Multiplied out: pow() of a negative number is undefined, and some cards
  // draw the hop enormous for it.
  float c1 = 1.70158, c3 = c1 + 1.0, m = k - 1.0;
  return 1.0 + c3 * m * m * m + c1 * m * m;
}
float flash(float at) { return uReplay > at ? exp(-(uReplay - at) * 2.4) : 0.0; }
`;

const NODE_VS = `${COMMON}
layout(location = 0) in vec3 aPos;
layout(location = 1) in vec3 aNormal;
layout(location = 2) in vec3 aBary;
layout(location = 3) in vec4 iPlace;
layout(location = 4) in vec4 iColor;
layout(location = 5) in vec4 iMotion;
uniform vec3 uEye;
out vec3 vNormal; out vec3 vBary; out vec3 vColor; out vec3 vView; out float vGlow;
mat3 turn(float yaw, float tilt) {
  float cy = cos(yaw), sy = sin(yaw), ct = cos(tilt), st = sin(tilt);
  return mat3(cy, 0.0, -sy, 0.0, 1.0, 0.0, sy, 0.0, cy) * mat3(1.0, 0.0, 0.0, 0.0, ct, st, 0.0, -st, ct);
}
void main() {
  mat3 r = turn(uTime * iMotion.y * uMotion + iMotion.x, iMotion.w);
  vec3 world = drift(iPlace.xyz, iMotion.x) + r * aPos * iPlace.w * grow(iMotion.z);
  vNormal = r * aNormal;
  vBary = aBary;
  vColor = iColor.rgb;
  vView = uEye - world;
  vGlow = iColor.a + flash(iMotion.z);
  gl_Position = uViewProj * vec4(world, 1.0);
}`;

const NODE_FS = `#version 300 es
precision highp float;
in vec3 vNormal; in vec3 vBary; in vec3 vColor; in vec3 vView; in float vGlow;
out vec4 outColor;
void main() {
  vec3 n = normalize(vNormal);
  float facing = abs(dot(n, normalize(vView)));
  float rim = pow(1.0 - facing, 2.2);
  vec3 a = smoothstep(vec3(0.0), fwidth(vBary) * 1.5, vBary);
  float edge = 1.0 - min(min(a.x, a.y), a.z);
  float light = 0.5 + 0.5 * abs(dot(n, normalize(vec3(0.4, 0.9, 0.3))));
  vec3 c = vColor * (0.05 + 0.1 * light + rim * 0.5) + vColor * edge * (0.85 + vGlow) + vec3(edge * vGlow * 0.3);
  outColor = vec4(c, 1.0);
}`;

const HALO_VS = `${COMMON}
layout(location = 0) in vec4 aPlace;
layout(location = 1) in vec4 aColor;
layout(location = 2) in vec2 aMotion;
out vec3 vColor; out float vGlow;
void main() {
  vec4 clip = uViewProj * vec4(drift(aPlace.xyz, aMotion.x), 1.0);
  float g = aColor.a + flash(aMotion.y);
  float grown = clamp((uReplay - aMotion.y) / 0.55, 0.0, 1.0);
  gl_Position = clip;
  gl_PointSize = clip.w > 0.0 ? min(uMaxPoint, aPlace.w * (3.0 + g * 2.5) * uPixels / clip.w) * grown : 0.0;
  vColor = aColor.rgb;
  vGlow = g;
}`;

const HALO_FS = `#version 300 es
precision highp float;
in vec3 vColor; in float vGlow;
out vec4 outColor;
void main() {
  vec2 q = gl_PointCoord * 2.0 - 1.0;
  float r2 = dot(q, q);
  if (r2 > 1.0) discard;
  outColor = vec4(vColor * exp(-r2 * 5.0) * (0.16 + 0.45 * vGlow) * (1.0 - r2), 1.0);
}`;

const EDGE_VS = `${COMMON}
layout(location = 0) in vec2 aCorner;
layout(location = 1) in vec4 iA;
layout(location = 2) in vec4 iB;
layout(location = 3) in vec4 iColor;
layout(location = 4) in vec4 iTiming;
uniform vec2 uHalf;
out float vT; out float vSide; out vec3 vColor;
flat out float vProgress; flat out float vStrength; flat out float vPulse;
void main() {
  vec4 ca = uViewProj * vec4(drift(iA.xyz, iA.w), 1.0);
  vec4 cb = uViewProj * vec4(drift(iB.xyz, iB.w), 1.0);
  vec2 d = (cb.xy / max(cb.w, 1e-3) - ca.xy / max(ca.w, 1e-3)) * uHalf;
  float len = length(d);
  vec2 dir = len > 1e-4 ? d / len : vec2(1.0, 0.0);
  vec4 c = mix(ca, cb, aCorner.x);
  c.xy += vec2(-dir.y, dir.x) * aCorner.y * iTiming.z * uDpr / uHalf * c.w;
  gl_Position = c;
  float k = clamp((uReplay - iTiming.x) / max(iTiming.y, 1e-3), 0.0, 1.0);
  vProgress = uReplay < iTiming.x ? -1.0 : k * k * (3.0 - 2.0 * k);
  vT = aCorner.x;
  vSide = aCorner.y;
  vColor = iColor.rgb;
  vStrength = iColor.a;
  vPulse = iTiming.w;
}`;

const EDGE_FS = `#version 300 es
precision highp float;
uniform float uTime;
in float vT; in float vSide; in vec3 vColor;
flat in float vProgress; flat in float vStrength; flat in float vPulse;
out vec4 outColor;
void main() {
  if (vT > vProgress) discard;
  float core = 1.0 - abs(vSide);
  core *= core;
  float tip = vProgress < 1.0 ? exp(-abs(vProgress - vT) * 28.0) : 0.0;
  float pulse = vPulse > 0.0 ? pow(max(0.0, sin((vT * 2.0 - uTime * vPulse) * 6.2831853)), 30.0) : 0.0;
  outColor = vec4(vColor * core * (vStrength + pulse * 1.6 + tip * 3.0), 1.0);
}`;

const PACKET_VS = `${COMMON}
layout(location = 0) in vec4 aA;
layout(location = 1) in vec4 aB;
layout(location = 2) in vec4 aColor;
layout(location = 3) in vec3 aTiming;
out vec3 vColor;
void main() {
  // A packet with an offset goes round again for as long as the page is open,
  // fading as it goes: a server giving away what it should not.
  bool loops = aTiming.z > 0.0;
  float k = loops ? fract(uTime * uMotion / aTiming.y + aTiming.z) : (uReplay - aTiming.x) / aTiming.y;
  if (uReplay < aTiming.x || k < 0.0 || k > 1.0) { gl_Position = vec4(2.0, 2.0, 2.0, 1.0); gl_PointSize = 0.0; return; }
  float e = loops ? k : k * k * (3.0 - 2.0 * k);
  vec4 clip = uViewProj * vec4(mix(drift(aA.xyz, aA.w), drift(aB.xyz, aB.w), e), 1.0);
  gl_Position = clip;
  gl_PointSize = clip.w > 0.0 ? min(uMaxPoint, aColor.a * uPixels / clip.w) * (loops ? 1.0 - k : 1.0) : 0.0;
  vColor = aColor.rgb;
}`;

const PACKET_FS = `#version 300 es
precision highp float;
in vec3 vColor;
out vec4 outColor;
void main() {
  vec2 q = gl_PointCoord * 2.0 - 1.0;
  float r2 = dot(q, q);
  if (r2 > 1.0) discard;
  outColor = vec4((vColor * exp(-r2 * 7.0) + vec3(exp(-r2 * 40.0))) * (1.0 - r2), 1.0);
}`;

const STAR_VS = `${COMMON}
layout(location = 0) in vec4 aStar;
out float vShine;
void main() {
  float a = uTime * 0.006 * uMotion;
  vec3 p = mat3(cos(a), 0.0, -sin(a), 0.0, 1.0, 0.0, sin(a), 0.0, cos(a)) * aStar.xyz;
  gl_Position = uViewProj * vec4(p, 1.0);
  float size = 0.7 + fract(aStar.w * 7.13) * 1.8;
  gl_PointSize = size * uDpr;
  vShine = (0.35 + 0.65 * fract(aStar.w * 3.7)) * (0.75 + 0.25 * sin(uTime * (0.6 + fract(aStar.w) * 1.5) + aStar.w * 40.0) * uMotion);
}`;

const STAR_FS = `#version 300 es
precision highp float;
in float vShine;
out vec4 outColor;
void main() {
  vec2 q = gl_PointCoord * 2.0 - 1.0;
  float r2 = dot(q, q);
  if (r2 > 1.0) discard;
  outColor = vec4(vec3(0.62, 0.74, 1.0) * vShine * (1.0 - r2) * 0.55, 1.0);
}`;

const FLOOR_VS = `${COMMON}
layout(location = 0) in vec2 aXZ;
uniform float uFloorY;
out vec2 vXZ;
void main() {
  vXZ = aXZ;
  gl_Position = uViewProj * vec4(aXZ.x, uFloorY, aXZ.y, 1.0);
}`;

const FLOOR_FS = `#version 300 es
precision highp float;
uniform float uTime;
uniform float uMotion;
uniform float uFloorR;
uniform vec3 uTone;
in vec2 vXZ;
out vec4 outColor;
void main() {
  float r = length(vXZ);
  float fade = 1.0 - smoothstep(uFloorR * 0.35, uFloorR, r);
  float s = fract((atan(vXZ.y, vXZ.x) - uTime * 0.5) / 6.2831853);
  float sweep = pow(1.0 - s, 8.0) * uMotion;
  float ring = exp(-abs(r - mod(uTime * 4.0, uFloorR * 1.4)) * 1.1) * uMotion;
  outColor = vec4(uTone * fade * (0.09 + sweep * 0.4 + ring * 0.35), 1.0);
}`;

/* ── the renderer ──────────────────────────────────────────────────────── */

class Renderer {
  #gl;
  #programs = {};
  #shapes = {};
  #halo;
  #edges;
  #packets;
  #stars;
  #floor;
  maxPoint = 64;

  constructor(canvas) {
    const gl = canvas.getContext("webgl2", { antialias: true, alpha: false, powerPreference: "default", depth: false });
    if (!gl) throw new Error("no webgl2");
    this.#gl = gl;
    this.maxPoint = gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)[1];

    const programs = {
      node: [NODE_VS, NODE_FS], halo: [HALO_VS, HALO_FS], edge: [EDGE_VS, EDGE_FS],
      packet: [PACKET_VS, PACKET_FS], star: [STAR_VS, STAR_FS], floor: [FLOOR_VS, FLOOR_FS],
    };
    for (const [name, [vs, fs]] of Object.entries(programs)) this.#programs[name] = this.#link(vs, fs);

    for (const [name, data] of Object.entries(SHAPES)) {
      const vao = gl.createVertexArray();
      gl.bindVertexArray(vao);
      this.#buffer(data);
      this.#attrib(0, 3, 36, 0);
      this.#attrib(1, 3, 36, 12);
      this.#attrib(2, 3, 36, 24);
      const instances = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, instances);
      this.#attrib(3, 4, STRIDE.node * 4, 0, 1);
      this.#attrib(4, 4, STRIDE.node * 4, 16, 1);
      this.#attrib(5, 4, STRIDE.node * 4, 32, 1);
      this.#shapes[name] = { vao, instances, vertices: data.length / 9, count: 0 };
    }

    this.#halo = this.#points([[0, 4, 0], [1, 4, 16], [2, 2, 32]], STRIDE.halo * 4);
    this.#packets = this.#points([[0, 4, 0], [1, 4, 16], [2, 4, 32], [3, 3, 48]], STRIDE.packet * 4);

    const corners = new Float32Array([0, -1, 1, -1, 1, 1, 0, -1, 1, 1, 0, 1]);
    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    this.#buffer(corners);
    this.#attrib(0, 2, 8, 0);
    const instances = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, instances);
    for (let i = 0; i < 4; i++) this.#attrib(i + 1, 4, STRIDE.edge * 4, i * 16, 1);
    this.#edges = { vao, instances, count: 0 };

    gl.bindVertexArray(null);
    gl.disable(gl.DEPTH_TEST);
    gl.disable(gl.CULL_FACE);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE);
  }

  get context() { return this.#gl; }

  #link(vsText, fsText) {
    const gl = this.#gl;
    const compile = (type, text) => {
      const shader = gl.createShader(type);
      gl.shaderSource(shader, text);
      gl.compileShader(shader);
      if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader));
      return shader;
    };
    const program = gl.createProgram();
    gl.attachShader(program, compile(gl.VERTEX_SHADER, vsText));
    gl.attachShader(program, compile(gl.FRAGMENT_SHADER, fsText));
    gl.linkProgram(program);
    if (!gl.getProgramParameter(program, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(program));
    const uniforms = {};
    for (let i = 0; i < gl.getProgramParameter(program, gl.ACTIVE_UNIFORMS); i++) {
      const { name } = gl.getActiveUniform(program, i);
      uniforms[name] = gl.getUniformLocation(program, name);
    }
    return { program, uniforms };
  }

  #buffer(data, usage = this.#gl.STATIC_DRAW) {
    const gl = this.#gl;
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, data, usage);
    return buffer;
  }

  #attrib(location, size, stride, offset, divisor = 0) {
    const gl = this.#gl;
    gl.enableVertexAttribArray(location);
    gl.vertexAttribPointer(location, size, gl.FLOAT, false, stride, offset);
    gl.vertexAttribDivisor(location, divisor);
  }

  #points(layout, stride) {
    const gl = this.#gl;
    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    for (const [location, size, offset] of layout) this.#attrib(location, size, stride, offset);
    return { vao, buffer, count: 0 };
  }

  #fill(buffer, data) {
    const gl = this.#gl;
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, data, gl.DYNAMIC_DRAW);
  }

  // Each of these replaces what the scene is made of. They are called when
  // the walk is (re)played or a hop is picked, never every frame.
  nodes(byShape) {
    for (const [name, shape] of Object.entries(this.#shapes)) {
      const data = byShape[name] ?? [];
      shape.count = data.length / STRIDE.node;
      this.#fill(shape.instances, new Float32Array(data));
    }
  }
  halos(data) { this.#halo.count = data.length / STRIDE.halo; this.#fill(this.#halo.buffer, new Float32Array(data)); }
  edges(data) { this.#edges.count = data.length / STRIDE.edge; this.#fill(this.#edges.instances, new Float32Array(data)); }
  packets(data) { this.#packets.count = data.length / STRIDE.packet; this.#fill(this.#packets.buffer, new Float32Array(data)); }

  stars(count) {
    const data = new Float32Array(count * 4);
    for (let i = 0; i < count; i++) {
      const u = Math.random() * 2 - 1;
      const a = Math.random() * Math.PI * 2;
      const r = 90 + Math.random() * 110;
      const s = Math.sqrt(1 - u * u);
      data.set([r * s * Math.cos(a), r * u, r * s * Math.sin(a), Math.random()], i * 4);
    }
    const vao = this.#gl.createVertexArray();
    this.#gl.bindVertexArray(vao);
    this.#buffer(data);
    this.#attrib(0, 4, 16, 0);
    this.#stars = { vao, count };
  }

  floor(radius) {
    const lines = [];
    const step = 2.5;
    for (let r = step; r <= radius; r += step) {
      const n = Math.max(24, Math.round(r * 6));
      for (let i = 0; i < n; i++) {
        const a = (i / n) * Math.PI * 2;
        const b = ((i + 1) / n) * Math.PI * 2;
        lines.push(r * Math.cos(a), r * Math.sin(a), r * Math.cos(b), r * Math.sin(b));
      }
    }
    for (let i = 0; i < 24; i++) {
      const a = (i / 24) * Math.PI * 2;
      lines.push(Math.cos(a) * step, Math.sin(a) * step, Math.cos(a) * radius, Math.sin(a) * radius);
    }
    const vao = this.#gl.createVertexArray();
    this.#gl.bindVertexArray(vao);
    this.#buffer(new Float32Array(lines));
    this.#attrib(0, 2, 8, 0);
    this.#floor = { vao, count: lines.length / 2, radius };
  }

  draw(frame) {
    const gl = this.#gl;
    gl.viewport(0, 0, frame.width, frame.height);
    gl.clearColor(0.018, 0.024, 0.05, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);

    const use = (name) => {
      const { program, uniforms } = this.#programs[name];
      gl.useProgram(program);
      const set = (key, fn, ...value) => uniforms[key] && gl[fn](uniforms[key], ...value);
      set("uViewProj", "uniformMatrix4fv", false, frame.viewProj);
      set("uTime", "uniform1f", frame.time);
      set("uReplay", "uniform1f", frame.replay);
      set("uMotion", "uniform1f", frame.motion);
      set("uPixels", "uniform1f", frame.pixels);
      set("uMaxPoint", "uniform1f", this.maxPoint);
      set("uDpr", "uniform1f", frame.dpr);
      set("uEye", "uniform3fv", frame.eye);
      set("uHalf", "uniform2f", frame.width / 2, frame.height / 2);
      set("uFloorY", "uniform1f", frame.floorY);
      set("uFloorR", "uniform1f", this.#floor?.radius ?? 1);
      set("uTone", "uniform3fv", TONES.info);
    };

    if (this.#stars) {
      use("star");
      gl.bindVertexArray(this.#stars.vao);
      gl.drawArrays(gl.POINTS, 0, this.#stars.count);
    }
    if (this.#floor) {
      use("floor");
      gl.bindVertexArray(this.#floor.vao);
      gl.drawArrays(gl.LINES, 0, this.#floor.count);
    }
    if (this.#edges.count) {
      use("edge");
      gl.bindVertexArray(this.#edges.vao);
      gl.drawArraysInstanced(gl.TRIANGLES, 0, 6, this.#edges.count);
    }
    if (this.#halo.count) {
      use("halo");
      gl.bindVertexArray(this.#halo.vao);
      gl.drawArrays(gl.POINTS, 0, this.#halo.count);
    }
    use("node");
    for (const shape of Object.values(this.#shapes)) {
      if (!shape.count) continue;
      gl.bindVertexArray(shape.vao);
      gl.drawArraysInstanced(gl.TRIANGLES, 0, shape.vertices, shape.count);
    }
    if (this.#packets.count) {
      use("packet");
      gl.bindVertexArray(this.#packets.vao);
      gl.drawArrays(gl.POINTS, 0, this.#packets.count);
    }
    gl.bindVertexArray(null);
  }
}

/* ── sound ─────────────────────────────────────────────────────────────── */

// Everything is synthesised, nothing is fetched. A low drone under the whole
// scene, a beacon placed where the answer is, and a note for each hop as it
// arrives, placed where the hop is: with the listener riding the camera,
// turning the scene turns the sound with it.
const NOTES = [220, 261.63, 293.66, 329.63, 392, 440, 523.25, 587.33, 659.25, 783.99, 880];

class Sound {
  #ctx = null;
  #master = null;
  #out = null;
  #tap = null;
  #beacon = null;
  on = false;

  async toggle(beaconAt) {
    if (this.on) {
      this.on = false;
      this.#master?.gain.setTargetAtTime(0, this.#ctx.currentTime, 0.2);
      setTimeout(() => !this.on && this.#ctx?.suspend(), 900);
      return false;
    }
    if (!this.#ctx) this.#start(beaconAt);
    await this.#ctx.resume();
    this.#master.gain.setTargetAtTime(0.7, this.#ctx.currentTime, 0.4);
    this.on = true;
    return true;
  }

  #start(beaconAt) {
    const ctx = this.#ctx = new AudioContext();
    const squash = this.#out = new DynamicsCompressorNode(ctx, { threshold: -18, ratio: 4 });
    squash.connect(ctx.destination);
    this.#master = new GainNode(ctx, { gain: 0 });
    this.#master.connect(squash);

    // The drone: three detuned voices under a filter that breathes.
    const filter = new BiquadFilterNode(ctx, { type: "lowpass", frequency: 420, Q: 5 });
    const breath = new OscillatorNode(ctx, { frequency: 0.06 });
    const depth = new GainNode(ctx, { gain: 220 });
    breath.connect(depth).connect(filter.frequency);
    breath.start();
    const pad = new GainNode(ctx, { gain: 0.05 });
    filter.connect(pad).connect(this.#master);
    for (const [frequency, type, detune] of [[55, "sawtooth", 0], [82.41, "triangle", 6], [110, "sine", -5]]) {
      const voice = new OscillatorNode(ctx, { frequency, type, detune });
      voice.connect(filter);
      voice.start();
    }

    // The air: noise, band-passed and kept quiet.
    const noise = ctx.createBuffer(1, ctx.sampleRate * 2, ctx.sampleRate);
    const samples = noise.getChannelData(0);
    for (let i = 0; i < samples.length; i++) samples[i] = Math.random() * 2 - 1;
    const air = new AudioBufferSourceNode(ctx, { buffer: noise, loop: true });
    air.connect(new BiquadFilterNode(ctx, { type: "bandpass", frequency: 900, Q: 0.7 }))
      .connect(new GainNode(ctx, { gain: 0.012 })).connect(this.#master);
    air.start();

    if (beaconAt) {
      const panner = this.#panner(beaconAt, 5);
      const tremolo = new GainNode(ctx, { gain: 0.02 });
      const lfo = new OscillatorNode(ctx, { frequency: 0.35 });
      lfo.connect(new GainNode(ctx, { gain: 0.015 })).connect(tremolo.gain);
      lfo.start();
      tremolo.connect(panner).connect(this.#master);
      for (const frequency of [523.25, 784.0]) {
        const voice = new OscillatorNode(ctx, { frequency, type: "sine" });
        voice.connect(tremolo);
        voice.start();
      }
      this.#beacon = panner;
    }
  }

  #panner([x, y, z], refDistance = 4) {
    return new PannerNode(this.#ctx, {
      panningModel: "HRTF", distanceModel: "inverse", refDistance, rolloffFactor: 1.1,
      positionX: x, positionY: y, positionZ: z,
    });
  }

  listen(eye, forward, up) {
    if (!this.on) return;
    const listener = this.#ctx.listener;
    const t = this.#ctx.currentTime;
    if (listener.positionX) {
      const params = [listener.positionX, listener.positionY, listener.positionZ, listener.forwardX, listener.forwardY,
        listener.forwardZ, listener.upX, listener.upY, listener.upZ];
      [...eye, ...forward, ...up].forEach((value, i) => params[i].setTargetAtTime(value, t, 0.05));
    } else {
      listener.setPosition(...eye);
      listener.setOrientation(...forward, ...up);
    }
  }

  // A note for a hop arriving: deeper hops higher, trouble lower and rough,
  // the answer as a chord.
  arrive(hop, tone, final) {
    if (!this.on) return;
    const ctx = this.#ctx;
    const t = ctx.currentTime;
    const base = NOTES[Math.min(hop.depth, NOTES.length - 1)];
    const trouble = tone === "bad" || tone === "warn";
    const quiet = hop.step.kind === "skipped" || hop.step.aside;
    const envelope = new GainNode(ctx, { gain: 0 });
    const peak = quiet ? 0.035 : final ? 0.16 : 0.1;
    envelope.gain.setValueAtTime(0, t);
    envelope.gain.linearRampToValueAtTime(peak, t + 0.008);
    envelope.gain.exponentialRampToValueAtTime(0.0001, t + (final ? 2.4 : 1.1));
    envelope.connect(this.#panner(hop.pos)).connect(this.#master);

    const voices = final ? [1, 1.5, 2] : trouble ? [0.5, 0.53] : [1, 2];
    for (const ratio of voices) {
      const osc = new OscillatorNode(ctx, { frequency: base * ratio, type: trouble ? "triangle" : "sine" });
      osc.connect(envelope);
      osc.start(t);
      osc.stop(t + (final ? 2.5 : 1.2));
    }
  }

  tick() {
    if (!this.on) return;
    const ctx = this.#ctx;
    const t = ctx.currentTime;
    const gain = new GainNode(ctx, { gain: 0.018 });
    gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.05);
    gain.connect(this.#master);
    const osc = new OscillatorNode(ctx, { frequency: 2400 });
    osc.connect(gain);
    osc.start(t);
    osc.stop(t + 0.06);
  }

  // The answer landing: a soft note at each hop as the bead reaches it, rising
  // as it climbs. They are all set going at once, timed from where the replay
  // is now.
  land(legs, at) {
    if (!this.on) return;
    const ctx = this.#ctx;
    const now = ctx.currentTime;
    legs.forEach((leg, i) => {
      const t = now + Math.max(0, leg.leave + leg.travel - at);
      const envelope = new GainNode(ctx, { gain: 0 });
      envelope.gain.setValueAtTime(0, t);
      envelope.gain.linearRampToValueAtTime(0.06, t + 0.005);
      envelope.gain.exponentialRampToValueAtTime(0.0001, t + 0.6);
      envelope.connect(this.#panner(leg.to.pos)).connect(this.#master);
      const osc = new OscillatorNode(ctx, { frequency: NOTES[Math.min(i + 4, NOTES.length - 1)], type: "sine" });
      osc.connect(envelope);
      osc.start(t);
      osc.stop(t + 0.65);
    });
  }

  // What is heard, for a film to carry; nothing while the sound is off.
  stream() {
    if (!this.on) return null;
    if (!this.#tap) {
      this.#tap = new MediaStreamAudioDestinationNode(this.#ctx);
      this.#out.connect(this.#tap);
    }
    return this.#tap.stream;
  }

  sweep() {
    if (!this.on) return;
    const ctx = this.#ctx;
    const t = ctx.currentTime;
    const gain = new GainNode(ctx, { gain: 0 });
    gain.gain.linearRampToValueAtTime(0.05, t + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, t + 0.35);
    gain.connect(this.#master);
    const osc = new OscillatorNode(ctx, { frequency: 300, type: "sine" });
    osc.frequency.exponentialRampToValueAtTime(1200, t + 0.3);
    osc.connect(gain);
    osc.start(t);
    osc.stop(t + 0.4);
  }
}

/* ── the page ──────────────────────────────────────────────────────────── */

const page = await fetch("page.json", { cache: "no-store" }).then((answer) => answer.json());
const walk = page.trace;
const hops = flatten(walk.root);
const result = resultOf(hops[0]);

// The way to the answer, which is drawn brighter than the rest.
const onPath = new Set();
for (let hop = result; hop; hop = hop.parent) onPath.add(hop);

for (const hop of hops) {
  const kind = kindOf(hop.step.kind);
  hop.kind = kind;
  hop.tone = hop.step.kind === "answer" && hop.step.aside ? "info" : kind.tone;
  hop.phase = (hop.id * 2.399963) % (Math.PI * 2);
  hop.size = kind.size * (hop.step.aside ? 0.6 : 1) * (hop === result ? 1.3 : 1);
  hop.dim = hop.step.kind === "skipped" ? 0.5 : hop.step.aside ? 0.65 : 1;
}

const bounds = layout(hops);

// A name left pointing at nothing hangs a snapped thread off the hop that
// showed it, down and out, clear of the ring below.
for (const hop of hops) {
  if (hop.step.dangling) hop.shard = add(hop.pos, add(scale(norm([hop.pos[0], 0, hop.pos[2]]), 0.7), [0, -1.9, 0]));
}

/* ── the HUD ──────────────────────────────────────────────────────────── */

document.title = `${walk.question.name} ${walk.question.type} · dnstree 3d`;
$("q-type").textContent = walk.question.type;
$("q-class").textContent = walk.question.class;

// The name decodes itself, the way a film would have it.
function decode(node, text) {
  if (reduced.matches) {
    node.textContent = text;
    return;
  }
  const glyphs = "▚▞▙▟░▒#%&*+=<>/\\0123456789abcdef";
  const start = performance.now();
  const step = (now) => {
    const k = (now - start) / 900;
    node.textContent = [...text].map((ch, i) =>
      ch === "." || i / text.length < k ? ch : glyphs[(Math.random() * glyphs.length) | 0]).join("");
    if (k < 1) requestAnimationFrame(step);
    else node.textContent = text;
  };
  requestAnimationFrame(step);
}
decode($("q-name"), walk.question.name);

const decided = verdictOf(hops, result);
const verdict = $("verdict");
verdict.textContent = decided.text;
verdict.classList.add(`tone-${decided.tone}`);

const askedHops = hops.filter((hop) => asked(hop.step));
const servers = new Set(askedHops.map((hop) => hop.step.server?.ip).filter(Boolean)).size;
const resolvers = walk.resolvers ?? [];
const differing = resolvers.filter((r) => r.match === "differs").length;
const chain = chainState(hops);
const stat = (tone, ...kids) => el("li", { class: tone ? `tone-${tone}` : null }, ...kids);
$("stats").append(...[
  stat(null, "walked in ", el("b", { text: took(walk.elapsed_ms) })),
  stat(null, el("b", { text: String(askedHops.length) }), " queries"),
  stat(null, el("b", { text: String(servers) }), " servers"),
  resolvers.length === 1
    ? stat(differing ? "warn" : null, "a resolver in ", el("b", { text: took(resolvers[0].elapsed_ms) }), differing ? " · answers differently" : "")
    : resolvers.length
      ? stat(differing ? "warn" : null, el("b", { text: String(resolvers.length) }), " resolvers",
        differing ? ` · ${differing} answer differently` : " · all agree")
      : null,
  chain ? stat(trustTone(chain), el("b", { text: chain }), " chain") : null,
].filter(Boolean));

$("built").textContent = `dnstree ${page.page.version} · walked ${new Date(page.page.generated).toLocaleString()}`;
if (walk.warnings?.length) {
  $("warnings").textContent = walk.warnings.join(" · ");
}

// The legend names only what this walk has in it.
const seen = new Set(hops.map((hop) => hop.step.kind));
$("legend").append(...[
  ...Object.entries(KINDS).filter(([name]) => seen.has(name)).map(([name, kind]) =>
    el("li", { style: `color:${toCss(TONES[kind.tone])}` }, el("i"), el("span", { class: "dim", text: name }))),
  chain ? el("li", { style: `color:${toCss(TONES[trustTone(chain)])}` }, el("i", { style: "border-radius:50%;rotate:0deg" }),
    el("span", { class: "dim", text: "chain of trust" })) : null,
  hops.some((hop) => hop.shard) ? el("li", { style: `color:${toCss(TONES.warn)}` }, el("i", { style: "width:1px;rotate:20deg" }),
    el("span", { class: "dim", text: "dangling" })) : null,
  hops.some(leaks) ? el("li", { style: `color:${toCss(TONES.bad)}` }, el("i", { style: "width:4px;height:4px;border-radius:50%" }),
    el("span", { class: "dim", text: "open to strangers" })) : null,
].filter(Boolean));

if (page.findings?.length) {
  const button = $("c-findings");
  button.hidden = false;
  $("f-list").append(...page.findings.map((finding) =>
    el("p", { class: `level-${finding.level}` }, el("span", { class: "topic", text: finding.topic }), finding.text)));
}

/* ── the labels ────────────────────────────────────────────────────────── */

const tagLayer = $("tags");
for (const hop of hops) {
  hop.tag = el("div", {
    class: `tag${hop.step.aside ? " aside" : ""}`,
    style: `--tone:${toCss(TONES[hop.tone])}`,
  }, el("b", { text: titleOf(hop.step) }), el("span", { text: subtitleOf(hop, result) }));
  hop.shown = { x: -1, y: -1, o: -1 };
  tagLayer.append(hop.tag);
}

/* ── the inspector ─────────────────────────────────────────────────────── */

const facts = (step) => factsOf(step).flatMap(([term, value, tone]) =>
  [el("dt", { text: term }), el("dd", { class: tone ? `tone-${tone}` : null, text: value })]);

function inspect(hop) {
  const panel = $("inspector");
  if (!hop) {
    panel.hidden = true;
    return;
  }
  const { step } = hop;
  panel.style.setProperty("--tone", toCss(TONES[hop.tone]));
  $("i-kind").textContent = [step.aside ? "aside" : null, step.kind, hop === result ? "· where the walk ended" : null].filter(Boolean).join(" ");
  $("i-title").textContent = titleOf(step);
  $("i-sub").textContent = step.server?.ip ? `${step.server.ip}${step.server.port && step.server.port !== 53 ? `:${step.server.port}` : ""}` : "";
  $("i-says").textContent = hop.kind.says;
  $("i-facts").replaceChildren(...facts(step));
  $("i-records").replaceChildren(...(step.records ?? []).map((rr) =>
    el("li", {}, el("span", { text: rr.name }), el("span", { class: "t", text: rr.type }), el("span", { class: "ttl", text: `${rr.ttl} ` }), rr.data)));
  panel.hidden = false;
}

/* ── the scene ─────────────────────────────────────────────────────────── */

const canvas = $("scene");
let renderer;
try {
  renderer = new Renderer(canvas);
} catch {
  // Nothing below has anything to draw on, so the module waits forever rather
  // than failing into the console.
  $("nogl").hidden = false;
  await new Promise(() => {});
}
canvas.addEventListener("webglcontextlost", (event) => {
  event.preventDefault();
  $("nogl").hidden = false;
  $("nogl").firstElementChild.textContent = "the graphics card let go of the scene; reloading the page brings it back.";
});

renderer.stars(reduced.matches ? 600 : 1400);
renderer.floor(bounds.radius + 6);

const epoch = performance.now();
const clock = () => (performance.now() - epoch) / 1000;
let motion = reduced.matches ? 0 : 1;

const state = { hovered: null, picked: null };

function glowOf(hop) {
  if (hop === state.picked) return 1.3;
  if (hop === state.hovered) return 0.8;
  if (hop === result) return 0.55;
  return onPath.has(hop) ? 0.25 : 0;
}

// The instances are rebuilt whenever what is lit changes; the positions,
// the floating and the arrival are worked out on the card.
function upload() {
  stale = true;
  const { byShape, halos } = nodesOf(hops, glowOf);
  renderer.nodes(byShape);
  renderer.halos(halos);
}

function wire() {
  const { edges, packets } = wiresOf(hops, { onPath, result, floor: bounds.floor, landing });
  renderer.edges(edges);
  renderer.packets(packets);
}

// The replay runs on a clock of its own, which the scrubber can hold or wind
// back while the scene goes on floating. Without motion it stands at the end,
// and only the scrubber moves it.
const replay = { at: 0, end: 0, held: false };
let arrivals = [];
let heard = 0;
let landing = [];
let landed = false;
function play() {
  schedule(hops);
  arrivals = [...hops].sort((a, b) => a.at - b.at);
  landing = landingOf(trail);
  const lands = landing.at(-1) ? landing.at(-1).leave + landing.at(-1).travel : 0;
  replay.end = Math.max(arrivals.at(-1).at, lands) + 0.6;
  replay.at = motion ? 0 : replay.end + 3;
  heard = motion ? 0 : arrivals.length;
  landed = !motion;
  upload();
  wire();
  marks();
  follow = motion ? { until: replay.end + 0.6 } : null;
}

const scrub = $("s-time");
function marks() {
  $("s-marks").replaceChildren(...hops.filter((hop) => asked(hop.step)).map((hop) => el("i", {
    class: onPath.has(hop) ? "path" : null,
    style: `left:${(hop.at / replay.end * 100).toFixed(2)}%;--tone:${toCss(TONES[hop.tone])}`,
  })));
}

// Sounds already behind the replay are not played again, and the camera leans
// towards whichever hop the replay is at.
function wind(to) {
  replay.at = clamp(to, 0, replay.end);
  heard = arrivals.findIndex((hop) => hop.at > replay.at);
  if (heard === -1) heard = arrivals.length;
  landed = !landing.length || replay.at >= landing[0].leave;
  if (motion && !state.picked && replay.at < replay.end) follow = { until: replay.end + 0.6 };
  stale = true;
}
scrub.addEventListener("input", () => wind(scrub.value / 1000 * replay.end));
scrub.addEventListener("pointerdown", () => { replay.held = true; });
for (const type of ["pointerup", "pointercancel"]) {
  addEventListener(type, () => {
    if (!replay.held) return;
    replay.held = false;
    scrub.blur();
  });
}

/* ── the camera ────────────────────────────────────────────────────────── */

// Framed from a little above, and aimed below the middle so that the bottom of
// the cone clears the controls.
const FOV = 0.8;
const fitFor = (aspect) => {
  const tall = Math.tan(FOV / 2);
  const wide = tall * aspect;
  return Math.max(12, 1.5 * Math.max(bounds.height / 2 / tall, bounds.spread / wide));
};
const fit = fitFor(innerWidth / innerHeight);
const home = { yaw: 0.6, pitch: 0.32, dist: fit, target: add(bounds.centre, [0, -Math.min(bounds.height * 0.12, 1.5), 0]) };
const camera = { ...home, target: [...home.target] };
const goal = { dist: fit, target: [...home.target], yaw: null, pitch: null };
const spin = { yaw: 0, pitch: 0 };
let orbiting = !reduced.matches;
let lastInput = -10;
let follow = null;

function eyeOf() {
  const c = Math.cos(camera.pitch);
  return add(camera.target, [camera.dist * c * Math.sin(camera.yaw), camera.dist * Math.sin(camera.pitch), camera.dist * c * Math.cos(camera.yaw)]);
}

function step(dt, now) {
  if (ride.on) {
    rideAlong(dt, now);
    return;
  }
  const ease = 1 - Math.exp(-dt * 4);
  const idle = now - lastInput > 3;

  camera.yaw += spin.yaw * dt;
  camera.pitch = clamp(camera.pitch + spin.pitch * dt, -1.25, 1.35);
  const friction = Math.exp(-dt * 3.2);
  spin.yaw *= friction;
  spin.pitch *= friction;
  if (orbiting && idle && motion) camera.yaw += dt * 0.07;

  // While the walk is being replayed the camera leans towards the hop that
  // just arrived, unless somebody has taken hold of it.
  if (follow && replay.at < follow.until && idle) {
    const latest = arrivals.findLast((hop) => hop.at <= replay.at && asked(hop.step));
    if (latest) goal.target = add(home.target, scale(sub(latest.pos, home.target), 0.35));
  } else if (follow && replay.at >= follow.until) {
    if (!state.picked) goal.target = [...home.target];
    follow = null;
  }

  if (goal.yaw !== null) {
    camera.yaw += (goal.yaw - camera.yaw) * ease;
    camera.pitch += (goal.pitch - camera.pitch) * ease;
    if (Math.abs(goal.yaw - camera.yaw) < 0.001) goal.yaw = goal.pitch = null;
  }
  camera.dist += (goal.dist - camera.dist) * ease;
  camera.target = add(camera.target, scale(sub(goal.target, camera.target), ease));
}

function reset() {
  riding(false);
  goal.dist = home.dist = fitFor(innerWidth / innerHeight);
  goal.target = [...home.target];
  // Back the short way round.
  const turns = Math.round((camera.yaw - home.yaw) / (Math.PI * 2));
  goal.yaw = home.yaw + turns * Math.PI * 2;
  goal.pitch = home.pitch;
  pick(null);
}

/* ── riding along ──────────────────────────────────────────────────────── */

// The camera can ride the question down the bright trail, behind it and a
// little above, dipping into each cut as it reaches one and going slowly
// round the answer at the end. Taking hold of the scene hands it back.
const trail = trailOf(result);
const ride = { on: false, turn: 0 };

function riding(on) {
  on = on && motion > 0 && trail.length > 0;
  if (on === ride.on) return;
  ride.on = on;
  controls.ride.setAttribute("aria-pressed", String(on));
  if (!on) return;
  pick(null);
  follow = null;
  spin.yaw = spin.pitch = 0;
  goal.yaw = goal.pitch = null;
  goal.dist = 7;
  ride.turn = 0;
  if (replay.at >= replay.end) play();
}

function rideAlong(dt, now) {
  const at = rideAt(trail, replay.at, now, motion);
  ride.turn = at.done ? ride.turn + dt * 0.15 : 0;
  const ease = 1 - Math.exp(-dt * 2.2);
  camera.yaw += around(behind(at.heading) + ride.turn - camera.yaw) * ease;
  camera.pitch += (0.42 - 0.14 * Math.exp(-at.since * 3) - camera.pitch) * ease;
  camera.dist += (goal.dist - camera.dist) * ease;
  camera.target = mix(camera.target, mix(at.at, at.ahead, 0.25), 1 - Math.exp(-dt * 5));
  goal.target = [...camera.target];
}

function focus(hop) {
  goal.target = [...hop.pos];
  goal.dist = Math.min(goal.dist, Math.max(12, fit * 0.55));
  follow = null;
}

/* ── picking ───────────────────────────────────────────────────────────── */

let frame = null;

// The hop under a point of the screen, found by projecting every hop rather
// than casting a ray: there are a few hundred of them at most.
function hopAt(x, y) {
  if (!frame) return null;
  const now = frame.time;
  let best = null;
  let bestDepth = Infinity;
  for (const hop of hops) {
    if (hop.at > frame.replay) continue;
    const [cx, cy, w] = project(frame.viewProj, drift(hop.pos, hop.phase, now, motion));
    if (w <= 0) continue;
    const sx = (cx / w * 0.5 + 0.5) * frame.cssWidth;
    const sy = (0.5 - cy / w * 0.5) * frame.cssHeight;
    const reach = Math.max(12, hop.size * 1.3 * frame.pixels / frame.dpr / w);
    if (Math.hypot(sx - x, sy - y) < reach && w < bestDepth) {
      best = hop;
      bestDepth = w;
    }
  }
  return best;
}

function pick(hop, { quiet = false } = {}) {
  if (state.picked === hop) return;
  state.picked?.tag.classList.remove("picked");
  state.picked = hop;
  hop?.tag.classList.add("picked");
  if (hop) riding(false);
  inspect(hop);
  upload();
  if (hop) {
    focus(hop);
    if (!quiet) sound.sweep();
  }
}

// The hops worth stepping through, which leaves out the servers nobody asked.
const stops = hops.filter((hop) => hop.step.kind !== "skipped");
const stepThrough = (by) => pick(stepFrom(stops, state.picked, by));

/* ── input ─────────────────────────────────────────────────────────────── */

const sound = new Sound();
const pointers = new Map();
let pressed = null;

canvas.addEventListener("pointerdown", (event) => {
  canvas.setPointerCapture(event.pointerId);
  pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
  pressed = { x: event.clientX, y: event.clientY, moved: 0, pan: event.shiftKey || event.button === 2 };
  canvas.classList.add("dragging");
  lastInput = clock();
  goal.yaw = goal.pitch = null;
  follow = null;
});

canvas.addEventListener("pointermove", (event) => {
  const was = pointers.get(event.pointerId);
  if (!was) {
    const hop = hopAt(event.clientX, event.clientY);
    if (hop !== state.hovered) {
      state.hovered = hop;
      canvas.classList.toggle("pointing", !!hop);
      upload();
      if (hop) sound.tick();
    }
    return;
  }
  const dx = event.clientX - was.x;
  const dy = event.clientY - was.y;
  pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
  pressed.moved += Math.abs(dx) + Math.abs(dy);
  lastInput = clock();

  if (pointers.size === 2) {
    // Two fingers: the distance between them is the zoom.
    const [a, b] = [...pointers.values()];
    const spread = Math.hypot(a.x - b.x, a.y - b.y);
    if (pressed.spread) goal.dist = clamp(goal.dist * (pressed.spread / spread), 4, 140);
    pressed.spread = spread;
    return;
  }
  // Turning or moving the scene takes the camera back; a click, or a pinch
  // that only zooms as the wheel does, leaves the ride going.
  if (pressed.moved >= 6) riding(false);
  if (pressed.pan) {
    const eye = eyeOf();
    const forward = norm(sub(camera.target, eye));
    const right = norm(cross(forward, [0, 1, 0]));
    const up = cross(right, forward);
    const k = camera.dist * 0.0018;
    goal.target = add(goal.target, add(scale(right, -dx * k), scale(up, dy * k)));
    return;
  }
  camera.yaw -= dx * 0.006;
  camera.pitch = clamp(camera.pitch + dy * 0.005, -1.25, 1.35);
  spin.yaw = -dx * 0.006 / Math.max(frame?.dt ?? 0.016, 0.008) * 0.5;
  spin.pitch = dy * 0.005 / Math.max(frame?.dt ?? 0.016, 0.008) * 0.5;
});

const release = (event) => {
  pointers.delete(event.pointerId);
  if (pointers.size) return;
  canvas.classList.remove("dragging");
  if (pressed && pressed.moved < 6) {
    pick(hopAt(event.clientX, event.clientY));
    spin.yaw = spin.pitch = 0;
  }
  pressed = null;
};
canvas.addEventListener("pointerup", release);
canvas.addEventListener("pointercancel", release);
canvas.addEventListener("contextmenu", (event) => event.preventDefault());

canvas.addEventListener("wheel", (event) => {
  event.preventDefault();
  goal.dist = clamp(goal.dist * Math.exp(event.deltaY * 0.0012), 4, 140);
  lastInput = clock();
}, { passive: false });

const controls = {
  replay: $("c-replay"), orbit: $("c-orbit"), ride: $("c-ride"), sound: $("c-sound"), film: $("c-film"),
  reset: $("c-reset"), findings: $("c-findings"),
};
controls.ride.hidden = !motion || !trail.length;
// A click leaves the focus where it was, so that the keys go on meaning what
// they say rather than pressing the button last clicked.
for (const button of document.querySelectorAll(".dock button")) {
  button.addEventListener("mousedown", (event) => event.preventDefault());
}
controls.replay.addEventListener("click", () => play());
controls.reset.addEventListener("click", () => reset());
controls.orbit.addEventListener("click", () => {
  orbiting = !orbiting;
  controls.orbit.setAttribute("aria-pressed", String(orbiting));
});
controls.orbit.setAttribute("aria-pressed", String(orbiting));
controls.ride.addEventListener("click", () => {
  if (ride.on) reset();
  else riding(true);
});
controls.sound.addEventListener("click", async () => {
  try {
    const on = await sound.toggle(result?.pos);
    controls.sound.setAttribute("aria-pressed", String(on));
  } catch {
    controls.sound.disabled = true;
    controls.sound.title = "this browser cannot make sound";
  }
});
controls.film.addEventListener("click", () => filming(!film.recorder));
controls.findings.addEventListener("click", () => {
  const panel = $("findings");
  panel.hidden = !panel.hidden;
  controls.findings.setAttribute("aria-pressed", String(!panel.hidden));
});
$("i-close").addEventListener("click", () => pick(null));
$("i-next").addEventListener("click", () => stepThrough(1));
$("i-prev").addEventListener("click", () => stepThrough(-1));

addEventListener("keydown", (event) => {
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  // The help sheet is modal: the scene behind it takes no keys but the one
  // that closes it.
  const open = document.querySelector(":popover-open");
  if (open) {
    if (event.key === "Escape" || event.key === "?") open.hidePopover();
    return;
  }
  if (event.target instanceof HTMLButtonElement && (event.key === " " || event.key === "Enter")) return;
  if (event.target === scrub && event.key.startsWith("Arrow")) return;
  const turn = 0.12;
  const keys = {
    ArrowLeft: () => { camera.yaw += turn; },
    ArrowRight: () => { camera.yaw -= turn; },
    ArrowUp: () => { camera.pitch = clamp(camera.pitch + turn, -1.25, 1.35); },
    ArrowDown: () => { camera.pitch = clamp(camera.pitch - turn, -1.25, 1.35); },
    "+": () => { goal.dist = clamp(goal.dist * 0.85, 4, 140); },
    "=": () => { goal.dist = clamp(goal.dist * 0.85, 4, 140); },
    "-": () => { goal.dist = clamp(goal.dist / 0.85, 4, 140); },
    n: () => stepThrough(1),
    j: () => stepThrough(1),
    p: () => stepThrough(-1),
    k: () => stepThrough(-1),
    " ": () => play(),
    o: () => controls.orbit.click(),
    f: () => !controls.ride.hidden && controls.ride.click(),
    m: () => controls.sound.click(),
    c: () => !controls.film.hidden && controls.film.click(),
    r: () => reset(),
    e: () => !controls.findings.hidden && controls.findings.click(),
    "?": () => $("help").togglePopover(),
    Escape: () => {
      if (!$("findings").hidden) controls.findings.click();
      else pick(null);
    },
  };
  const act = keys[event.key];
  if (!act) return;
  event.preventDefault();
  lastInput = clock();
  if (event.key.startsWith("Arrow")) riding(false);
  act();
});

reduced.addEventListener("change", () => {
  motion = reduced.matches ? 0 : 1;
  if (!motion) {
    if (ride.on) reset();
    filming(false);
    play();
  }
  controls.ride.hidden = !motion || !trail.length;
  controls.film.hidden = !motion || !format;
  orbiting = orbiting && !reduced.matches;
  controls.orbit.setAttribute("aria-pressed", String(orbiting));
});

/* ── filming ───────────────────────────────────────────────────────────── */

// A film is the replay recorded as it plays, from the start, with whatever the
// camera does meanwhile: orbiting, riding, or being turned by hand. The name
// and the labels live on the page rather than the canvas, so each frame is
// drawn again onto one of its own with them over it. Nothing leaves the
// browser; the film is handed to the viewer as a download.
const format = typeof MediaRecorder === "undefined" || !HTMLCanvasElement.prototype.captureStream
  ? null
  : formatFor((type) => MediaRecorder.isTypeSupported(type));
controls.film.hidden = !motion || !format;
const film = { recorder: null, timer: 0, frame: null, pen: null, w: 0, h: 0 };

function filming(on) {
  if (!on) {
    clearTimeout(film.timer);
    if (film.recorder?.state === "recording") film.recorder.stop();
    return;
  }
  if (film.recorder || !format || !motion) return;
  const [width, height] = framed(canvas.width, canvas.height);
  film.frame = Object.assign(document.createElement("canvas"), { width, height });
  film.pen = film.frame.getContext("2d");
  const stream = film.frame.captureStream(30);
  for (const track of sound.stream()?.getAudioTracks() ?? []) stream.addTrack(track);

  const chunks = [];
  const recorder = film.recorder = new MediaRecorder(stream, { mimeType: format.type, videoBitsPerSecond: 8e6 });
  recorder.addEventListener("dataavailable", (event) => event.data.size && chunks.push(event.data));
  recorder.addEventListener("stop", () => {
    film.recorder = null;
    controls.film.setAttribute("aria-pressed", "false");
    const link = el("a", { href: URL.createObjectURL(new Blob(chunks, { type: format.type })), download: filmName(walk.question, format) });
    link.click();
    setTimeout(() => URL.revokeObjectURL(link.href), 60_000);
  });
  play();
  film.w = sized.w;
  film.h = sized.h;
  // A timer rather than the frames: a tab in the background draws none, and
  // the recorder would go on filming the last one until it came back.
  film.timer = setTimeout(() => filming(false), filmLength(replay.end) * 1000);
  recorder.start(1000);
  controls.film.setAttribute("aria-pressed", "true");
}

// One frame of the film: the scene as just drawn, the labels where the page
// has them, and the question in the corner.
function shoot() {
  // The frame was cut to the window's shape when the film began; a window
  // that changes shape would come out squashed, so the film ends there.
  if (sized.w !== film.w || sized.h !== film.h) {
    filming(false);
    return;
  }
  const { frame, pen } = film;
  pen.drawImage(canvas, 0, 0, frame.width, frame.height);
  pen.save();
  pen.scale(frame.width / sized.w, frame.height / sized.h);
  pen.textBaseline = "middle";
  for (const hop of hops) {
    if (!hop.place || hop.place.o < 0.03) continue;
    const { x, y, o } = hop.place;
    pen.globalAlpha = o;
    pen.font = "600 12px ui-monospace, Menlo, monospace";
    pen.fillStyle = toCss(TONES[hop.tone]);
    pen.fillText(hop.tag.firstChild.textContent, x, y - 7);
    pen.font = "11px ui-monospace, Menlo, monospace";
    pen.fillStyle = "rgb(150 165 190)";
    pen.fillText(hop.tag.lastChild.textContent, x, y + 8);
  }
  pen.globalAlpha = 1;
  pen.textBaseline = "alphabetic";
  pen.fillStyle = "rgb(120 140 170)";
  pen.font = "12px ui-monospace, Menlo, monospace";
  pen.fillText("dnstree//3d", 28, 38);
  pen.fillStyle = "rgb(230 238 248)";
  pen.font = "300 34px ui-monospace, Menlo, monospace";
  pen.fillText(walk.question.name, 28, 78);
  pen.fillStyle = toCss(TONES.info);
  pen.font = "13px ui-monospace, Menlo, monospace";
  pen.fillText(`${walk.question.type} ${walk.question.class}`, 28, 102);
  pen.restore();
}

/* ── every frame ───────────────────────────────────────────────────────── */

// The scene is drawn at the screen's density up to a limit, and at less when
// the frames start to come slowly: a fan spinning up is worse than a softer
// picture. The budget only ever comes down; the cap on a very large window,
// about six million pixels, is worked out again whenever the window changes.
let budget = Math.min(devicePixelRatio || 1, 2);
let dpr = budget;
let slow = 0;
let sized = { w: 0, h: 0, dpr: 0 };

function resize() {
  const w = canvas.clientWidth;
  const h = canvas.clientHeight;
  dpr = Math.min(budget, Math.max(1, Math.sqrt(6e6 / Math.max(1, w * h))));
  if (w === sized.w && h === sized.h && dpr === sized.dpr) return false;
  canvas.width = Math.max(1, Math.round(w * dpr));
  canvas.height = Math.max(1, Math.round(h * dpr));
  sized = { w, h, dpr };
  return true;
}

// Without motion nothing moves on its own, so a frame is only drawn when
// something has changed: the camera still easing, a hop picked, the window
// resized.
let stale = true;
const settled = () =>
  Math.abs(spin.yaw) + Math.abs(spin.pitch) < 1e-3 && goal.yaw === null &&
  Math.abs(goal.dist - camera.dist) < 1e-3 && Math.hypot(...sub(goal.target, camera.target)) < 1e-3;

// Which labels matter most, when there is not room for all of them.
function rankOf(hop) {
  if (hop === state.picked) return 0;
  if (hop === state.hovered) return 1;
  if (hop === result) return 2;
  if (hop.step.kind === "zone") return 3;
  if (onPath.has(hop)) return 4;
  if (hop.tone === "bad" || hop.tone === "warn" || hop.shard || leaks(hop)) return 5;
  return hop.step.aside ? 7 : hop.step.kind === "skipped" ? 8 : 6;
}

// Every label follows its hop across the screen, as far as declutter leaves
// room for it.
function placeTags(viewProj, now, width, height, pixels) {
  const showing = [];
  for (const hop of hops) {
    hop.place = null;
    const wanted = hop.at <= replay.at && (hop.step.kind !== "skipped" || hop === state.hovered || hop === state.picked);
    if (!wanted) continue;
    const [cx, cy, w] = project(viewProj, drift(hop.pos, hop.phase, now, motion));
    if (w <= 0.5) continue;
    const reach = hop.size * (hop.step.dnssec ? 1.8 : 1.2) * pixels / dpr / w;
    const x = (cx / w * 0.5 + 0.5) * width + reach + 16;
    const y = (0.5 - cy / w * 0.5) * height;
    if (x > width || y < -20 || y > height + 20) continue;
    hop.box ??= { w: hop.tag.offsetWidth, h: hop.tag.offsetHeight };
    let o = clamp(1.5 - w / (camera.dist * 1.25), 0.2, 1) * (hop.step.aside ? 0.75 : 1);
    if (hop === state.picked || hop === state.hovered) o = 1;
    hop.place = { x, y, o, rank: rankOf(hop) };
    showing.push(hop);
  }
  declutter(showing);

  for (const hop of hops) {
    const tag = hop.tag;
    const { x, y, o } = hop.place ?? { x: hop.shown.x, y: hop.shown.y, o: 0 };
    if (Math.abs(x - hop.shown.x) > 0.3 || Math.abs(y - hop.shown.y) > 0.3) {
      tag.style.transform = `translate3d(${x.toFixed(1)}px, ${y.toFixed(1)}px, 0) translateY(-50%)`;
      hop.shown.x = x;
      hop.shown.y = y;
    }
    if (Math.abs(o - hop.shown.o) > 0.02) {
      tag.style.opacity = o.toFixed(2);
      hop.shown.o = o;
    }
  }
}

// A frame is slow against the fastest the screen has ever delivered, not a
// fixed figure: a browser that paces itself at 30 frames a second, as Safari
// does to save a battery, is not struggling.
let last = clock();
let fastest = Infinity;
let shownAt = -1;
function tick() {
  requestAnimationFrame(tick);
  const now = clock();
  const dt = Math.min(now - last, 0.1);
  // The replay keeps to the wall clock, so a slow card drops frames rather
  // than slowing the walk down.
  if (motion && !replay.held) replay.at += now - last;
  last = now;

  if (dt > 0) fastest = Math.min(fastest, dt);
  if (dt > Math.max(fastest * 1.5, 0.022)) slow++;
  else slow = Math.max(0, slow - 1);
  if (slow > 45 && budget > 1) {
    budget = Math.max(1, budget - 0.25);
    slow = 0;
  }
  if (resize()) stale = true;
  step(dt, now);
  if (!motion && !stale && settled() && now - lastInput > 0.5) return;
  stale = false;

  const eye = eyeOf();
  const aspect = canvas.width / canvas.height;
  const proj = perspective(FOV, aspect, 0.1, 500);
  const viewProj = multiply(proj, lookAt(eye, camera.target, [0, 1, 0]));
  const pixels = canvas.height * proj[5] * 0.5;
  frame = {
    viewProj, eye, time: now, replay: replay.at, dt, motion, pixels, dpr,
    width: canvas.width, height: canvas.height, cssWidth: sized.w, cssHeight: sized.h, floorY: bounds.floor,
  };
  renderer.draw(frame);
  placeTags(viewProj, now, sized.w, sized.h, pixels);
  // Drawn straight after the scene, before the browser clears what it drew.
  if (film.recorder) shoot();

  if (!landed && landing.length && replay.at >= landing[0].leave) {
    landed = true;
    if (!replay.held && replay.at - landing[0].leave < 0.25) sound.land(landing, replay.at);
  }

  // A note for each hop that has arrived since the last frame.
  while (heard < arrivals.length && arrivals[heard].at <= replay.at) {
    const hop = arrivals[heard++];
    if (!replay.held && replay.at - hop.at < 0.25) sound.arrive(hop, hop.tone, hop === result);
  }
  const at = Math.round(clamp(replay.at / replay.end, 0, 1) * 1000);
  if (!replay.held && Number(scrub.value) !== at) scrub.value = String(at);
  if (at !== shownAt) scrub.parentElement.style.setProperty("--at", `${at / 10}%`);
  shownAt = at;
  if (sound.on) {
    const forward = norm(sub(camera.target, eye));
    sound.listen(eye, forward, cross(norm(cross(forward, [0, 1, 0])), forward));
  }
}

play();
requestAnimationFrame(tick);
