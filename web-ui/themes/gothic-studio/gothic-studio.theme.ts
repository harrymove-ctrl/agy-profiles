// The gothic-studio theme. `astryx experimental theme editor` wrote this file once and never changes it again.
// The checked settings live in gothic-studio.settings.json and the generated gothic-studio.settings.ts;
// change them with `astryx experimental theme editor set gothic-studio ...`. Add your own changes below: they win over the settings.
import {defineTheme} from '@astryxdesign/core/theme';
import {gothicStudioSettings} from './gothic-studio.settings';

export const gothicStudioTheme = defineTheme({
  extends: gothicStudioSettings,
  name: 'gothic-studio',
  motion: {
    fast: 120,
    medium: 200,
    slow: 320,
    ratio: 0.75,
  },
  tokens: {
    '--color-background-body': '#0c0f12',
    '--color-background-surface': '#151a1f',
    '--color-background-card': '#181e24',
    '--color-background-muted': '#1e252c',
    '--color-background-popover': '#1c232a',
    '--color-border': '#e8f1f61f',
    '--color-border-emphasized': '#4b5560',
    '--focus-outline-color': '#8aa1d8',
  },
});
