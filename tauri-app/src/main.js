import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

const term = new Terminal({
  fontFamily: 'Cascadia Code, Consolas, monospace',
  fontSize: 14,
  theme: { background: '#000000', foreground: '#ffffff' },
  convertEol: true,
  cursorBlink: false
});

const fitAddon = new FitAddon();
term.loadAddon(fitAddon);

term.open(document.getElementById('terminal'));
fitAddon.fit();

window.addEventListener('resize', () => {
    fitAddon.fit();
});

listen('vora-output', (event) => {
    term.write(event.payload);
});

invoke('start_vora');
