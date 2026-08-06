import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import { enTranslation } from './en';
import { itTranslation } from './it';

export const translations = { en: enTranslation, it: itTranslation } as const;

const stored = localStorage.getItem('sip.language');
void i18n.use(initReactI18next).init({
  resources: { en: { translation: enTranslation }, it: { translation: itTranslation } },
  lng: stored === 'it' ? 'it' : 'en',
  fallbackLng: false,
  returnNull: false,
  interpolation: { escapeValue: false },
  parseMissingKeyHandler: key => { throw new Error(`MISSING_I18N_KEY:${key}`); }
});
export default i18n;
