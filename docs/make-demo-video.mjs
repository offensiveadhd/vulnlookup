// Render docs/demo.html to docs/demo.mp4 and docs/demo.gif with Playwright's Chromium + ffmpeg.
// Development only; the SVG is what the README shows. Usage:
//   node docs/make-demo-video.mjs [path-to-playwright-package-dir]
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkdirSync, rmSync, readdirSync } from 'node:fs';
import path from 'node:path';

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const pw = process.argv[2] || 'playwright';
const { chromium } = await import(pw.includes('/') || pw.includes('\\') ? pathToFileURL(path.join(pw, 'index.mjs')).href : pw);
const frames = path.join(here, 'demo-video-frames');
rmSync(frames, { recursive: true, force: true });
mkdirSync(frames);
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 940, height: 720 }, deviceScaleFactor: 1 });
await page.goto(pathToFileURL(path.join(here, 'demo.html')).href);
const fps = 10, seconds = 58;
for (let i = 0; i < fps * seconds; i++) {
  await page.screenshot({ path: path.join(frames, String(i).padStart(4, '0') + '.png') });
  await page.waitForTimeout(1000 / fps);
}
await browser.close();
const n = readdirSync(frames).length;
console.log(`captured ${n} frames`);
const run = (args) => { const r = spawnSync('ffmpeg', args, { stdio: 'inherit' }); if (r.status) process.exit(r.status); };
run(['-y', '-framerate', String(fps), '-i', path.join(frames, '%04d.png'), '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '28', path.join(here, 'demo.mp4')]);
run(['-y', '-framerate', String(fps), '-i', path.join(frames, '%04d.png'), '-vf', 'fps=8,scale=800:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=64[p];[s1][p]paletteuse=dither=bayer', path.join(here, 'demo.gif')]);
rmSync(frames, { recursive: true, force: true });
console.log('wrote demo.mp4 and demo.gif');
