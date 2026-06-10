import { en, type Messages } from './en.js';
import { ja } from './ja.js';

export type Locale = 'ja' | 'en';

export function detectLocale(env: NodeJS.ProcessEnv = process.env): Locale {
  const raw = env.LC_ALL || env.LC_MESSAGES || env.LANG || '';
  return raw.toLowerCase().startsWith('ja') ? 'ja' : 'en';
}

export function getMessages(locale: Locale): Messages {
  return locale === 'ja' ? ja : en;
}

export type { Messages };
