/** E2E-only page: renders the real Preview component with hostile HTML. Not part of the build. */
import { createRoot } from 'react-dom/client';
import { Preview } from '../src/features/inspector/Preview.tsx';

const TRACKER = `${location.origin}/__tracker`;

const hostile = `
  <style>@import url("${TRACKER}/import.css"); body { background: url("${TRACKER}/style-bg.png"); }</style>
  <link rel="stylesheet" href="${TRACKER}/link.css">
  <p style="background-image: url('${TRACKER}/inline-bg.png')">Hello</p>
  <img src="${TRACKER}/pixel.png" srcset="${TRACKER}/pixel-2x.png 2x">
  <img src="https://tracker.example/remote.png">
  <iframe src="${TRACKER}/frame.html"></iframe>
  <script>fetch("${TRACKER}/script")</script>
  <img src="x" onerror="fetch('${TRACKER}/onerror')">
  <a id="link" href="${TRACKER}/clicked">Click me</a>
`;

createRoot(document.getElementById('root')!).render(
  <Preview preview={{ text: null, html: hostile }} />,
);
