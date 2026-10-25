// Everything the page needs to know that is not in the data files.

/** The repository, for links to files and their commit history. */
export const REPO = 'diagnos-tech/audit';
export const BRANCH = 'develop';
export const GITHUB = `https://github.com/${REPO}`;

/** Where people without a clone point the verifier (-root). */
export const SITE = 'https://diagnos-tech.github.io/audit/';

/**
 * Data sets the page may load, by ?data= value. Anything else is ignored, so
 * a crafted link cannot make this page display data from another place.
 */
export const DATA_SETS = { '': '', examples: 'examples/' };

/**
 * How often to re-read latest.json. GitHub Pages serves files with a
 * ten-minute cache; the requests carry a per-minute query string so that a
 * refresh sees a new commit within a minute or two of it landing.
 */
export const REFRESH_MS = 4 * 60 * 1000;

/**
 * The witness commits at least once an hour (the hourly timestamp). Allowing
 * for the Pages deploy and its cache, a summary older than this means the
 * witness has stopped reporting.
 */
export const STALE_AFTER_MS = 90 * 60 * 1000;

/** Rows per page in the history table. */
export const PAGE_SIZE = 30;

/** Hours shown in the hourly strip. */
export const STRIP_HOURS = 24;

/** Display names of time-stamping authorities (keys/tsa/<provider>.pem). */
export const PROVIDERS = {
  freetsa: 'FreeTSA',
  digicert: 'DigiCert',
  sectigo: 'Sectigo',
  globalsign: 'GlobalSign',
  certum: 'Certum',
  apple: 'Apple',
  'example-tsa': 'Example TSA',
  'example-tsa-backup': 'Example backup TSA',
};
