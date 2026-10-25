// Strings and formatting in English and Brazilian Portuguese. The static
// HTML is written in English and carries data-i18n keys; everything else is
// rendered through t(). Times are shown in UTC, like the file names.

const en = {
  skip: 'Skip to content',
  brand: 'witness record',
  refresh: 'Refresh',
  'lang.switch': 'Ver em português',
  'example.title': 'Example data.',
  'example.body': 'Generated with example keys under examples/ to preview the page. These are not real records.',
  'example.leave': 'Show the real record',
  'example.clock': 'The clock is pinned to the examples: {time}.',
  title: 'Independent witness record',
  lede: "Every five minutes an independent witness checks that diagnos' transparency logs only ever grow, and cosigns what it saw. Every hour an outside time-stamping authority dates the whole record. This page shows those results; the commands at the end let you check them without trusting anyone, this page included.",
  'boot.title': 'The live view could not start.',
  'status.title': 'Status',
  'hourly.title': 'Hourly independent proof',
  'hourly.lede': "Each hour the witness hashes the latest tree head of every log together with the previous hour's record, and asks an RFC 3161 time-stamping authority to sign that hash with the time. Deleting or rewriting any past hour breaks every link after it.",
  'history.title': 'Witness history',
  'history.lede': 'One row per cosigned checkpoint: the witness only writes a record when a tree grew, with the proof that the new tree extends the old one.',
  'verify.title': 'How to verify',
  'verify.lede': "Don't take this page's word for it. These commands check the selected record with your own tools; VERIFY.md explains each step and what it proves.",
  'about.title': 'What this record proves',
  'about.proves': 'It proves',
  'about.p1': 'Each log only grew: every cosigned checkpoint extends the previous one, by a Merkle consistency proof anyone can recheck.',
  'about.p2': 'The log showed the witness one history: two different trees for the same size would be signed evidence, published as a finding.',
  'about.p3': 'When: an outside authority dated the whole record every hour, so it cannot be rewritten later without breaking the chain.',
  'about.not': 'It does not prove',
  'about.n1': 'What is inside the logs. Leaves are salted commitments; this repository never holds an entry or any personal data.',
  'about.n2': 'That diagnos logged everything it should. A witness sees the log, not the systems that write to it.',
  'about.n3': 'That the witness is honest on its own. That is why every record carries the log\'s own signature and a proof you can recheck against the log.',
  'footer.about': "Public record of the diagnos transparency witness. No build step, no third-party code: read the page's source.",
  'footer.data': 'Data',
  'footer.schemas': 'Schemas',
  'footer.security': 'Security',
  'footer.license': 'Licenses: code Apache-2.0, data CC0',

  'log.audit': 'Audit trail',
  'log.signs': 'Signatures',
  'health.fresh': 'Fresh',
  'health.stale': 'Stale',
  'health.finding': 'Finding',

  'verdict.fresh': 'All logs consistent',
  'verdict.fresh.body': 'The witness last reported {ago}, at {time}. Every log only grew, and there are no findings.',
  'verdict.stale': 'The witness is late',
  'verdict.stale.body': 'No report for {age} (last at {time}). The witness commits at least every hour, so nothing new is being witnessed until it reports again.',
  'verdict.finding': 'Finding: a log showed conflicting histories',
  'verdict.finding.body': 'The witness recorded evidence signed by the log itself. It stops cosigning a log after a finding. Details below.',
  'verdict.error': 'Could not load the record',
  'verdict.empty': 'Nothing published yet',
  'verdict.empty.body': 'The witness has not written its first record; this record starts with its first commit.',
  'verdict.empty.preview': 'Preview the page with example data',
  'verdict.retry': 'Try again',
  'witness.key': 'Witness key',

  'tree.entries': 'entries',
  'tree.grew': '+{n} at the latest growth',
  'tree.first': 'first witnessed checkpoint',
  'tree.root': 'Root hash',
  'tree.witnessed': 'Witnessed',
  'tree.checked': 'Checked',
  'tree.cosigned': 'Cosignature',
  'tree.cosigned.value': 'present, by {name}',
  'tree.record': 'Record (JSON)',
  'tree.history': 'History on GitHub',
  'tree.verify': 'Verify this record',

  'finding.equivocation': 'Equivocation',
  'finding.equivocation.body': 'The log signed two different trees of the same size. Only a log that shows different histories to different readers can do that.',
  'finding.rollback': 'Rollback',
  'finding.rollback.body': 'The log signed a smaller tree after the witness had cosigned a larger one.',
  'finding.inconsistent': 'Inconsistent history',
  'finding.inconsistent.body': 'The log could not prove that its new tree extends the one the witness cosigned.',
  'finding.in': '{kind} in {log}',
  'finding.detected': 'Detected',
  'finding.summary': 'Summary',
  'finding.evidence': 'Evidence',
  'finding.verify': 'Verify this finding',

  'hourly.latest': 'Latest timestamp',
  'hourly.empty': 'No hourly record yet.',
  'hourly.hour': 'Hour',
  'hourly.provider': 'Authority',
  'hourly.genTime': 'Attested time',
  'hourly.imprint': 'Imprint',
  'hourly.checked': 'Checked by the witness',
  'hourly.none': 'No token this hour: every authority failed. The record still links the chain.',
  'hourly.token': 'Token (.tsr)',
  'hourly.verify': 'Verify this hour',
  'hourly.strip': 'Last {n} hours',
  'hourly.strip.note': 'Select an hour to see how to verify it.',
  'hourly.earlier': 'Earlier',
  'hourly.later': 'Later',
  'hourly.state.ok': 'timestamped, linked',
  'hourly.state.fallback': 'timestamped by a backup authority',
  'hourly.state.gap': 'no token (all authorities failed)',
  'hourly.state.missing': 'no record',
  'hourly.state.broken': 'link does not match',
  'hourly.table': 'Hourly records from {from} to {to} UTC, newest first',
  'hourly.link': 'Link to previous hour (checked here)',
  'hourly.link.ok': 'matches {hour}',
  'hourly.link.bad': 'does NOT match {hour}',
  'hourly.link.first': 'first record',
  'hourly.link.unchecked': 'previous record not loaded',
  'hourly.files': 'Files',
  'hourly.chain.ok': 'Chain intact: all {n} links in this window match the previous record, checked in this browser.',
  'hourly.chain.bad': '{bad} of {n} links in this window do NOT match the previous record.',
  'hourly.chain.pending': 'Checking the links in this browser…',
  'hourly.chain.unknown': '{unknown} of {n} links could not be checked here (a record did not load).',

  'history.none': 'No witnessed checkpoint yet.',
  'history.month': 'Month',
  'history.newer': 'Newer',
  'history.older': 'Older',
  'history.range': '{from}–{to} of {total}',
  'history.empty': 'No witnessed checkpoints for this log in {month}.',
  'history.caption': '{log}: cosigned checkpoints in {month}, newest first',
  'history.time': 'Witnessed (UTC)',
  'history.size': 'Tree size',
  'history.growth': 'Growth',
  'history.root': 'Root hash',
  'history.links': 'Record',
  'history.json': 'JSON',
  'history.commit': 'commit',
  'history.select': 'verify',
  'history.select.label': 'Verify the record of {time}',

  'verify.selected': 'Selected: {what}',
  'verify.witness': 'witness record of {log} at {time} UTC',
  'verify.timestamp': 'hourly record of {hour} UTC',
  'verify.finding': 'finding in {log} at {time} UTC',
  'verify.clone': 'Get the record and the verifier',
  'verify.clone.note': 'A shallow clone is enough. The verifier needs Go 1.24 or later and nothing else.',
  'verify.witness.step': 'Check the log signature, the witness cosignature and the consistency proof',
  'verify.witness.note': 'Uses the keys in keys/. For an independent check, compare them with the keys diagnos publishes elsewhere, or pass your own copy with -keys.',
  'verify.log.step': 'Check against the log itself',
  'verify.log.note': "Rebuilds the consistency proof from the log's own hash tiles, up to the log's current checkpoint, without trusting the proof the witness recorded.",
  'verify.log.example': 'The example logs are not online, so this step only works on real records.',
  'verify.noclone.step': 'Or without cloning',
  'verify.ts.step': 'Check the hourly record, its links and its token',
  'verify.ts.note': '-openssl also verifies the authority\'s signature and certificate chain with openssl.',
  'verify.ts.byhand': 'Or by hand, with jq, sha256sum and openssl',
  'verify.ts.byhand.note': 'The first two lines must print the same hash; openssl must say "Verification: OK".',
  'verify.finding.step': 'Check that the finding is evidence',
  'verify.finding.note': 'Both checkpoints must carry the log\'s signature, and conflict the way the finding says.',
  'verify.doc': 'Read VERIFY.md',
  'verify.browser': 'Check in this browser',
  'verify.browser.note': 'Runs the same checks with this page\'s code and your browser\'s cryptography. Quick, but it trusts this page; the commands above do not.',
  'verify.browser.running': 'Checking…',
  'verify.browser.done': 'Done: {ok} of {total} checks passed.',
  'verify.browser.unsupported': 'This browser cannot verify Ed25519 signatures; use the commands above.',

  'check.logsig': 'Log signature',
  'check.cosig': 'Witness cosignature',
  'check.head': 'Tree head matches the note',
  'check.consistency': 'Consistency with the previous record',
  'check.first': 'First record of the log: nothing to prove',
  'check.imprint': 'Imprint = SHA-256 of the subject',
  'check.subject': 'Subject names {log} at size {size}',
  'check.prev': 'Link to the previous hour',
  'check.token': 'Token file matches its hash',
  'check.observed': 'Conflicting checkpoint signed by the log',
  'check.witnessed': 'Witnessed checkpoint signed by log and witness',
  'check.conflict': 'The two checkpoints conflict',

  'copy.what': 'Copy {what}',
  'copy.done': 'Copied {what}',
  'copy.failed': 'Copying failed; select the text and copy it by hand.',
  'what.root': 'root hash',
  'what.imprint': 'imprint',
  'what.command': 'command',

  'refresh.updated': 'Updated {ago}',
  'refresh.loading': 'Updating…',
  'refresh.failed': 'Update failed; retrying soon',
  'announce.grew': '{log} grew to {size} entries.',
  'announce.hour': 'New hourly timestamp for {hour} UTC.',
  'announce.health': 'Status changed: {health}.',
};

const pt = {
  skip: 'Pular para o conteúdo',
  brand: 'registro da testemunha',
  refresh: 'Atualizar',
  'lang.switch': 'View in English',
  'example.title': 'Dados de exemplo.',
  'example.body': 'Gerados com chaves de exemplo em examples/ para pré-visualizar a página. Não são registros reais.',
  'example.leave': 'Ver o registro real',
  'example.clock': 'O relógio está fixado nos exemplos: {time}.',
  title: 'Registro independente da testemunha',
  lede: 'A cada cinco minutos, uma testemunha independente confere que os logs de transparência da diagnos só crescem e cossina o que viu. A cada hora, uma autoridade de carimbo de tempo externa data o registro inteiro. Esta página mostra esses resultados; os comandos no fim permitem conferir tudo sem confiar em ninguém, nem nesta página.',
  'boot.title': 'A visualização ao vivo não pôde começar.',
  'status.title': 'Situação',
  'hourly.title': 'Prova independente a cada hora',
  'hourly.lede': 'A cada hora, a testemunha calcula o hash do último estado de cada log junto com o registro da hora anterior e pede a uma autoridade de carimbo de tempo (RFC 3161) que assine esse hash com a hora. Apagar ou reescrever qualquer hora passada quebra todos os elos seguintes.',
  'history.title': 'Histórico da testemunha',
  'history.lede': 'Uma linha por checkpoint cossinado: a testemunha só grava quando uma árvore cresceu, com a prova de que a árvore nova estende a anterior.',
  'verify.title': 'Como conferir',
  'verify.lede': 'Não acredite nesta página. Estes comandos conferem o registro selecionado com as suas próprias ferramentas; o VERIFY.md explica cada passo e o que ele prova.',
  'about.title': 'O que este registro prova',
  'about.proves': 'Prova',
  'about.p1': 'Que cada log só cresceu: todo checkpoint cossinado estende o anterior, por uma prova de consistência de Merkle que qualquer pessoa pode refazer.',
  'about.p2': 'Que o log mostrou à testemunha uma só história: duas árvores diferentes do mesmo tamanho seriam evidência assinada, publicada como achado.',
  'about.p3': 'Quando: uma autoridade externa datou o registro inteiro a cada hora, então ele não pode ser reescrito depois sem quebrar a corrente.',
  'about.not': 'Não prova',
  'about.n1': 'O que há dentro dos logs. As folhas são compromissos com sal; este repositório nunca guarda uma entrada nem dado pessoal.',
  'about.n2': 'Que a diagnos registrou tudo o que deveria. A testemunha vê o log, não os sistemas que escrevem nele.',
  'about.n3': 'Que a testemunha é honesta por si só. Por isso cada registro traz a assinatura do próprio log e uma prova que você refaz contra o log.',
  'footer.about': 'Registro público da testemunha de transparência da diagnos. Sem etapa de build, sem código de terceiros: leia o código da página.',
  'footer.data': 'Dados',
  'footer.schemas': 'Schemas',
  'footer.security': 'Segurança',
  'footer.license': 'Licenças: código Apache-2.0, dados CC0',

  'log.audit': 'Trilha de auditoria',
  'log.signs': 'Assinaturas',
  'health.fresh': 'Em dia',
  'health.stale': 'Atrasada',
  'health.finding': 'Achado',

  'verdict.fresh': 'Todos os logs consistentes',
  'verdict.fresh.body': 'A testemunha relatou {ago}, às {time}. Todos os logs só cresceram e não há achados.',
  'verdict.stale': 'A testemunha está atrasada',
  'verdict.stale.body': 'Sem relato há {age} (o último às {time}). A testemunha registra pelo menos a cada hora; até ela voltar, nada novo está sendo testemunhado.',
  'verdict.finding': 'Achado: um log mostrou histórias conflitantes',
  'verdict.finding.body': 'A testemunha registrou evidência assinada pelo próprio log. Depois de um achado ela para de cossinar o log. Detalhes abaixo.',
  'verdict.error': 'Não foi possível carregar o registro',
  'verdict.empty': 'Nada publicado ainda',
  'verdict.empty.body': 'A testemunha ainda não gravou o primeiro registro; este registro começa no primeiro commit dela.',
  'verdict.empty.preview': 'Ver a página com dados de exemplo',
  'verdict.retry': 'Tentar de novo',
  'witness.key': 'Chave da testemunha',

  'tree.entries': 'entradas',
  'tree.grew': '+{n} no último crescimento',
  'tree.first': 'primeiro checkpoint testemunhado',
  'tree.root': 'Hash da raiz',
  'tree.witnessed': 'Testemunhado',
  'tree.checked': 'Conferido',
  'tree.cosigned': 'Cossinatura',
  'tree.cosigned.value': 'presente, de {name}',
  'tree.record': 'Registro (JSON)',
  'tree.history': 'Histórico no GitHub',
  'tree.verify': 'Conferir este registro',

  'finding.equivocation': 'Equivocação',
  'finding.equivocation.body': 'O log assinou duas árvores diferentes do mesmo tamanho. Só um log que mostra histórias diferentes a leitores diferentes faz isso.',
  'finding.rollback': 'Retrocesso',
  'finding.rollback.body': 'O log assinou uma árvore menor depois de a testemunha cossinar uma maior.',
  'finding.inconsistent': 'História inconsistente',
  'finding.inconsistent.body': 'O log não conseguiu provar que a árvore nova estende a que a testemunha cossinou.',
  'finding.in': '{kind} em {log}',
  'finding.detected': 'Detectado',
  'finding.summary': 'Resumo',
  'finding.evidence': 'Evidência',
  'finding.verify': 'Conferir este achado',

  'hourly.latest': 'Último carimbo',
  'hourly.empty': 'Nenhum registro horário ainda.',
  'hourly.hour': 'Hora',
  'hourly.provider': 'Autoridade',
  'hourly.genTime': 'Hora atestada',
  'hourly.imprint': 'Imprint',
  'hourly.checked': 'Conferido pela testemunha',
  'hourly.none': 'Sem token nesta hora: todas as autoridades falharam. O registro mantém a corrente.',
  'hourly.token': 'Token (.tsr)',
  'hourly.verify': 'Conferir esta hora',
  'hourly.strip': 'Últimas {n} horas',
  'hourly.strip.note': 'Selecione uma hora para ver como conferi-la.',
  'hourly.earlier': 'Antes',
  'hourly.later': 'Depois',
  'hourly.state.ok': 'carimbada e encadeada',
  'hourly.state.fallback': 'carimbada por uma autoridade reserva',
  'hourly.state.gap': 'sem token (todas as autoridades falharam)',
  'hourly.state.missing': 'sem registro',
  'hourly.state.broken': 'elo não confere',
  'hourly.table': 'Registros horários de {from} a {to} UTC, do mais novo ao mais antigo',
  'hourly.link': 'Elo com a hora anterior (conferido aqui)',
  'hourly.link.ok': 'confere com {hour}',
  'hourly.link.bad': 'NÃO confere com {hour}',
  'hourly.link.first': 'primeiro registro',
  'hourly.link.unchecked': 'registro anterior não carregado',
  'hourly.files': 'Arquivos',
  'hourly.chain.ok': 'Corrente íntegra: os {n} elos desta janela conferem com o registro anterior, conferidos neste navegador.',
  'hourly.chain.bad': '{bad} de {n} elos desta janela NÃO conferem com o registro anterior.',
  'hourly.chain.pending': 'Conferindo os elos neste navegador…',
  'hourly.chain.unknown': '{unknown} de {n} elos não puderam ser conferidos aqui (um registro não carregou).',

  'history.none': 'Nenhum checkpoint testemunhado ainda.',
  'history.month': 'Mês',
  'history.newer': 'Mais novos',
  'history.older': 'Mais antigos',
  'history.range': '{from}–{to} de {total}',
  'history.empty': 'Nenhum checkpoint testemunhado deste log em {month}.',
  'history.caption': '{log}: checkpoints cossinados em {month}, do mais novo ao mais antigo',
  'history.time': 'Testemunhado (UTC)',
  'history.size': 'Tamanho',
  'history.growth': 'Crescimento',
  'history.root': 'Hash da raiz',
  'history.links': 'Registro',
  'history.json': 'JSON',
  'history.commit': 'commit',
  'history.select': 'conferir',
  'history.select.label': 'Conferir o registro de {time}',

  'verify.selected': 'Selecionado: {what}',
  'verify.witness': 'registro de testemunha de {log} em {time} UTC',
  'verify.timestamp': 'registro horário de {hour} UTC',
  'verify.finding': 'achado em {log} em {time} UTC',
  'verify.clone': 'Baixe o registro e o verificador',
  'verify.clone.note': 'Um clone raso basta. O verificador precisa do Go 1.24 ou mais novo e de nada mais.',
  'verify.witness.step': 'Confira a assinatura do log, a cossinatura da testemunha e a prova de consistência',
  'verify.witness.note': 'Usa as chaves em keys/. Para uma conferência independente, compare-as com as chaves que a diagnos publica em outros lugares, ou passe a sua cópia com -keys.',
  'verify.log.step': 'Confira contra o próprio log',
  'verify.log.note': 'Refaz a prova de consistência a partir dos tiles de hash do próprio log, até o checkpoint atual dele, sem confiar na prova que a testemunha gravou.',
  'verify.log.example': 'Os logs de exemplo não estão no ar, então este passo só funciona com registros reais.',
  'verify.noclone.step': 'Ou sem clonar',
  'verify.ts.step': 'Confira o registro horário, seus elos e o token',
  'verify.ts.note': '-openssl também confere a assinatura da autoridade e a cadeia de certificados com o openssl.',
  'verify.ts.byhand': 'Ou à mão, com jq, sha256sum e openssl',
  'verify.ts.byhand.note': 'As duas primeiras linhas devem imprimir o mesmo hash; o openssl deve dizer "Verification: OK".',
  'verify.finding.step': 'Confira que o achado é evidência',
  'verify.finding.note': 'Os dois checkpoints precisam ter a assinatura do log e conflitar como o achado diz.',
  'verify.doc': 'Ler o VERIFY.md',
  'verify.browser': 'Conferir neste navegador',
  'verify.browser.note': 'Roda as mesmas conferências com o código desta página e a criptografia do seu navegador. É rápido, mas confia nesta página; os comandos acima não.',
  'verify.browser.running': 'Conferindo…',
  'verify.browser.done': 'Pronto: {ok} de {total} conferências passaram.',
  'verify.browser.unsupported': 'Este navegador não confere assinaturas Ed25519; use os comandos acima.',

  'check.logsig': 'Assinatura do log',
  'check.cosig': 'Cossinatura da testemunha',
  'check.head': 'Estado da árvore confere com a nota',
  'check.consistency': 'Consistência com o registro anterior',
  'check.first': 'Primeiro registro do log: nada a provar',
  'check.imprint': 'Imprint = SHA-256 do assunto',
  'check.subject': 'O assunto aponta {log} no tamanho {size}',
  'check.prev': 'Elo com a hora anterior',
  'check.token': 'Arquivo do token confere com o hash',
  'check.observed': 'Checkpoint conflitante assinado pelo log',
  'check.witnessed': 'Checkpoint testemunhado assinado pelo log e pela testemunha',
  'check.conflict': 'Os dois checkpoints conflitam',

  'copy.what': 'Copiar {what}',
  'copy.done': '{what} copiado',
  'copy.failed': 'Não deu para copiar; selecione o texto e copie à mão.',
  'what.root': 'hash da raiz',
  'what.imprint': 'imprint',
  'what.command': 'comando',

  'refresh.updated': 'Atualizado {ago}',
  'refresh.loading': 'Atualizando…',
  'refresh.failed': 'Falha ao atualizar; nova tentativa em breve',
  'announce.grew': '{log} cresceu para {size} entradas.',
  'announce.hour': 'Novo carimbo horário de {hour} UTC.',
  'announce.health': 'A situação mudou: {health}.',
};

const dictionaries = { en, 'pt-BR': pt };
let lang = 'en';

/** Picks the language: a saved choice, else the browser's preference. */
export function initLang() {
  let saved = null;
  try { saved = localStorage.getItem('lang'); } catch { /* storage may be blocked */ }
  if (saved && dictionaries[saved]) lang = saved;
  else if ((navigator.languages ?? [navigator.language]).some((l) => /^pt\b/i.test(l))) lang = 'pt-BR';
  document.documentElement.lang = lang;
  return lang;
}

export function getLang() { return lang; }

export function setLang(next) {
  lang = dictionaries[next] ? next : 'en';
  document.documentElement.lang = lang;
  try { localStorage.setItem('lang', lang); } catch { /* fine: the choice lasts this visit */ }
}

/** Translates key, filling {name} placeholders from vars. */
export function t(key, vars = {}) {
  const text = dictionaries[lang][key] ?? en[key] ?? key;
  return text.replace(/\{(\w+)\}/g, (_, name) => String(vars[name] ?? `{${name}}`));
}

/** Like t(), but vars may be DOM nodes: returns parts to pass to h(). */
export function tn(key, vars = {}) {
  const text = dictionaries[lang][key] ?? en[key] ?? key;
  return text.split(/(\{\w+\})/).filter(Boolean).map((part) => {
    const name = /^\{(\w+)\}$/.exec(part)?.[1];
    return name && name in vars ? vars[name] : part;
  });
}

/** Applies translations to the static HTML (elements with data-i18n). */
export function translateStatic(root = document) {
  for (const el of root.querySelectorAll('[data-i18n]')) el.textContent = t(el.dataset.i18n);
}

/** The display name of a log. */
export function logName(log) {
  const key = `log.${log}`;
  return dictionaries[lang][key] ?? en[key] ?? log;
}

export const fmt = {
  number: (n) => new Intl.NumberFormat(lang).format(n),

  /** "2026-10-01 14:20:05", the UTC wall time, as in file names. */
  utc: (iso) => iso.replace('T', ' ').replace('Z', ''),

  /** "14:20", a UTC hour or minute. */
  hm: (iso) => iso.slice(11, 16),

  /** "October 2026" for "2026-10". */
  month: (month) => new Intl.DateTimeFormat(lang, { month: 'long', year: 'numeric', timeZone: 'UTC' })
    .format(new Date(`${month}-01T00:00:00Z`)),

  /** "3 minutes ago", "in 2 hours". */
  relative(ms) {
    const rtf = new Intl.RelativeTimeFormat(lang, { numeric: 'auto' });
    const s = Math.round(ms / 1000);
    const abs = Math.abs(s);
    if (abs < 60) return rtf.format(-s, 'second');
    if (abs < 3600) return rtf.format(-Math.round(s / 60), 'minute');
    if (abs < 86400 * 2) return rtf.format(-Math.round(s / 3600), 'hour');
    return rtf.format(-Math.round(s / 86400), 'day');
  },

  /** "2 h 10 min", a duration. */
  duration(ms) {
    const minutes = Math.max(0, Math.round(ms / 60000));
    const days = Math.floor(minutes / 1440);
    const hours = Math.floor((minutes % 1440) / 60);
    const parts = [];
    if (days) parts.push(`${days} d`);
    if (hours) parts.push(`${hours} h`);
    if (!days) parts.push(`${minutes % 60} min`);
    return parts.join(' ');
  },
};
