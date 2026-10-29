# Registro de auditoria da diagnos

[![Check](https://github.com/diagnos-tech/audit/actions/workflows/check.yml/badge.svg)](https://github.com/diagnos-tech/audit/actions/workflows/check.yml)
[![Data](https://github.com/diagnos-tech/audit/actions/workflows/data.yml/badge.svg)](https://github.com/diagnos-tech/audit/actions/workflows/data.yml)
[![Código: Apache-2.0](https://img.shields.io/badge/c%C3%B3digo-Apache--2.0-blue)](LICENSE)
[![Dados: CC BY-ND 4.0](https://img.shields.io/badge/dados-CC_BY--ND_4.0-lightgrey)](LICENSES/CC-BY-ND-4.0.txt)

**English:** [README.md](README.md) (a versão de referência; esta é a tradução)

Este repositório é o registro público e independente da **confidencialidade, integridade e
disponibilidade** da diagnos. A cada cinco minutos o auditor da diagnos confere quatro serviços, lê
os incidentes que a diagnos declarou, testemunha os logs de transparência da diagnos, publica o
resultado num bucket público da Scaleway e **grava os mesmos arquivos aqui, em `develop`, a cada
execução**. Os serviços são medidos de duas regiões, Europa e América Latina, por duas testemunhas
independentes. A cada hora, uma autoridade de carimbo de tempo externa (RFC 3161) data o registro
inteiro.

Pessoas mudam poucas coisas aqui: declaram incidentes por pull request e alteram os documentos, os
schemas, as chaves e o verificador. Tudo o que está em `data/` é escrito pelo auditor.

## Onde olhar

| O quê | Endereço |
| --- | --- |
| **A página de status** | <https://status.diagnos.health/> |
| Se essa página não abrir: a mesma página, servida pela Scaleway | <https://imgexam-auditor-production.s3-website.fr-par.scw.cloud/> |
| O registro, no GitHub | este repositório, ou <https://raw.githubusercontent.com/diagnos-tech/audit/develop/> |
| O registro, na Scaleway | <https://imgexam-auditor-production.s3.fr-par.scw.cloud/> |
| Mudanças assim que acontecem | [feeds](#feeds-e-assinaturas) em <https://status.diagnos.health/feeds/> |
| Confira você mesmo | [VERIFY.md](VERIFY.md) (em inglês: os comandos são os mesmos em qualquer idioma) |

`audit.diagnos.health` e a raiz de `transparency.diagnos.health` redirecionam para a página de
status. A página é construída e assinada pela pipeline da própria diagnos e só é publicada pelo
auditor depois que ele verifica a versão; este repositório guarda apenas os dados dela. A página é só
uma conveniência: o registro são os arquivos em [`data/v1/`](data/v1) e [`incidents/`](incidents), e
tudo o que a página afirma pode ser conferido a partir deles com ferramentas comuns, sem confiar na
diagnos, no auditor nem na página.

## As três dimensões

| Dimensão | O que se confere, a cada cinco minutos | Cor na página |
| --- | --- | --- |
| **Disponibilidade** | o `GET /healthz` de cada serviço responde 200 com um corpo bem formado, a tempo e com certificado TLS válido, da Europa e da América Latina; os checkpoints dos logs de transparência estão legíveis | verde: respondeu normalmente · amarelo: lento, certificado perto de vencer, ou alcançável de só uma região · vermelho: sem resposta válida |
| **Integridade** | a versão que cada serviço diz rodar foi assinada pelo workflow de CI da diagnos (Sigstore), com proveniência SLSA, e os arquivos servidos batem com o manifesto assinado; também que os logs de transparência testemunhados só cresceram | verde: verificada · amarelo: não dá para confirmar (sem evidência, verificação pendente) · vermelho: evidência inválida ou bytes diferentes |
| **Confidencialidade** | os incidentes que a diagnos declarou em [`incidents/`](incidents) e que afetam o serviço naquele momento; nada mais a colore | verde: nenhum declarado · amarelo: baixa ou média · vermelho: alta ou crítica |

Cinza quer dizer *não medido*: o auditor não rodou, ou o serviço não pôde ser alcançado (veja
[dado atrasado nunca é queda](#dado-atrasado-nunca-é-queda)). Incidentes também colorem
disponibilidade e integridade (veja [incidentes](#incidentes)). Os
serviços são `diagnos.health` (site e app), `vault.diagnos.health` (a API que guarda os exames
cifrados), `sign.diagnos.health` (assinatura de documentos) e `status.diagnos.health` (a própria
página de status: estática, servida no GitHub Pages e na cópia da Scaleway).

## Duas testemunhas, duas regiões

Os serviços são medidos de dois lugares ao mesmo tempo, cada um por uma **testemunha** própria, com
chave própria. Uma região na página é uma testemunha; a página nunca mostra o identificador de uma
testemunha sem o nome dela.

| Testemunha (id) | Região na página | Roda em | Chave |
| --- | --- | --- | --- |
| `europe` | Europa | Scaleway, Paris. É o único relógio e a única testemunha que publica: o registro de execução de cada intervalo é dela. | [`keys/witness/auditor.vkey`](keys/README.md) |
| `latam` | América Latina | Oracle Cloud, São Paulo. Não tem relógio e não publica nada; quando é chamada, mede de onde está, assina o que mediu e responde. | [`keys/witness/latam.vkey`](keys/README.md) |

Cada testemunha assina a própria medição, então um número da América Latina se confere com a chave
da América Latina, e não com a palavra da diagnos. O registro de execução traz as duas medições
assinadas e, ao lado delas, o resultado **combinado** de cada serviço, que o verificador recalcula a
partir delas. A combinação segue quatro regras:

- **Vermelho (fora do ar) só quando as testemunhas concordam.** As duas falham no mesmo intervalo,
  ou só uma mediu e a nova tentativa dela confirma a falha.
- **Amarelo, `regional`, quando uma falha e a outra não.** O serviço é alcançável de uma região e de
  outra não; a página diz qual. Nunca é vermelho por si só.
- **Testemunha em silêncio é neutra.** Se uma testemunha não respondeu, não foi verificada ou ficou
  sem tempo, a medição dela é *não medida* (cinza) naquele intervalo e a outra decide sozinha.
  Isso nunca é queda de serviço; depois de três execuções seguidas o fluxo de mudanças diz que
  as medições daquela testemunha estão indisponíveis, e depois de duas boas, que voltaram.
- **Evidência não é votação.** Um achado ou uma parada num log de transparência, visto por qualquer
  das testemunhas, conta: mostrar a uma região uma árvore diferente da outra é exatamente o ataque
  que uma segunda testemunha existe para pegar. Quando as duas leem raízes diferentes para o mesmo
  tamanho de um log, o log assinou duas árvores e o registro precisa dizer isso.

Para cada serviço e região, um arquivo de dia guarda a cor de cada intervalo e a latência de cada
sondagem bem-sucedida (288 valores, para que qualquer percentil possa ser recalculado), com o mínimo
(p0), p50, p75, p90, p95, p99, o máximo (p100), a média e o número de amostras. Os percentis são por
*posto mais próximo* sobre as sondagens que deram certo: um tempo esgotado é um erro, contado pela
classe (resolução de nome, conexão, handshake, tempo, 5xx, 4xx, asserção), nunca uma resposta muito
lenta. O tempo de cada sondagem é dividido em resolução, conexão, handshake, espera e transferência.

A chave da segunda testemunha é publicada depois, por pull request revisado. Enquanto ela não
existe, o verificador a trata como ausente, não como errada: tudo o mais nos registros da segunda
testemunha é conferido e o relatório diz, com um aviso, que as assinaturas deles não foram. Um
arquivo de chave que existe e está errado é uma falha.

## O que prova e o que não prova

| | Prova | Não prova |
| --- | --- | --- |
| **Disponibilidade** | A cada cinco minutos, de dois lugares independentes (Scaleway em Paris e Oracle Cloud em São Paulo), o `/healthz` de cada serviço respondeu 200 com um corpo bem formado e corretamente identificado, dentro do orçamento de latência, com certificado TLS válido, ou como falhou. Uma falha vista de só uma região aparece como tal. Lacunas no registro aparecem em cinza. | Que todo usuário conseguiu acessar o serviço (dois pontos de observação não são todas as redes; um problema de um provedor ou de um país fora deles pode não aparecer). Que as funções por trás do `/healthz` funcionam (ele não toca em banco de dados, por projeto). O que aconteceu entre duas sondagens: uma queda menor que cinco minutos pode passar. Que os logs de transparência aceitam escrita (só que os checkpoints estão legíveis). |
| **Integridade** | A versão que cada serviço diz rodar foi construída por um workflow de CI fixado, num branch fixado de um repositório fixado (pelo id numérico), a partir do commit que ela cita: o manifesto da versão está assinado via Sigstore e uma atestação de proveniência SLSA do mesmo digest foi assinada pela mesma identidade. Para conteúdo estático (diagnos.health, a página de status, os arquivos estáticos dos Workers) os bytes efetivamente servidos foram amostrados e batem com o manifesto assinado. | Que um Worker (vault, sign) roda o script que informa: o auditor não consegue ler o código dos Workers. Que o código-fonte não tem falhas ou portas dos fundos. Que a própria CI não foi comprometida (SLSA Build Nível 2, não 3). Que um arquivo estático alterado entre duas amostragens foi notado na hora: uma passada completa pelo manifesto leva de dezenas de minutos a muitas horas, conforme o tamanho dele. |
| **Confidencialidade** | Quais incidentes a diagnos declarou, contra quais serviços, com que gravidade e linha do tempo. Cada snapshot fixa o blob Git de cada arquivo de incidente e entra na corrente dos carimbos horários, então uma edição ou remoção posterior de uma declaração continua visível. | Que nada mais aconteceu. O auditor não detecta vazamentos: uma linha verde quer dizer *nenhum incidente declarado*, nada além. Declarar é um compromisso que a diagnos assume em público; este registro torna visível, não impossível, quebrá-lo depois. |
| **Testemunha** | Cada log de transparência só cresceu: todo checkpoint cossinado estende o anterior, por uma prova de consistência (RFC 9162) que qualquer pessoa recalcula, inclusive a partir dos tiles do próprio log. O log mostrou à testemunha uma só história (um segundo checkpoint conflitante vira um achado público). A cada hora uma autoridade independente assinou um hash que cobre o último estado das árvores, a hora anterior e o último registro de execução, então o passado não pode ser reescrito sem quebrar a corrente. | O que há nos logs: as folhas são compromissos com sal, e este repositório nunca guarda folha, entrada nem dado pessoal. Que a diagnos registrou tudo o que deveria: a testemunha vê o log, não os sistemas que escrevem nele. |

O auditor é operado pela diagnos. O que dá independência ao registro são os carimbos de tempo
RFC 3161 de terceiros a cada hora (que também fixam a corrente de registros de execução), os logs
públicos do Sigstore para as versões, o histórico público do Git deste repositório e a segunda
cópia do registro no bucket público: uma verificação horária compara registros de amostra das duas
cópias byte a byte, e uma diferença é uma falha a explicar.

## Os dois logs

| Log | Cada folha se compromete com | Origem do checkpoint | Leitura pública |
| --- | --- | --- | --- |
| `audit` | uma linha da trilha de auditoria da diagnos | `transparency.diagnos.health/audit/v1` | <https://transparency.diagnos.health/audit/v1/> |
| `signs` | uma assinatura eletrônica concluída | `transparency.diagnos.health/signs/v1` | <https://transparency.diagnos.health/signs/v1/> |

Os dois são logs [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) com
[checkpoints](https://c2sp.org/tlog-checkpoint) em [signed-note](https://c2sp.org/signed-note),
compatíveis byte a byte com o [Tessera](https://github.com/transparency-dev/tessera). A testemunha
cossina com uma chave [tlog-cosignature](https://c2sp.org/tlog-cosignature) (`cosignature/v1`) de
nome `witness.diagnos.health/auditor/v1`.

## Com que frequência atualiza

```
a cada 5 min   sonda 4 serviços, confere versões, lê incidentes, testemunha os dois logs
               ──► publica no bucket público ──► grava os mesmos arquivos em develop
a cada hora    carimba a hora (fixa também o último registro de execução)
               ──► registro horário + token RFC 3161, no mesmo commit
```

- Um **registro de execução** é gravado para cada intervalo de cinco minutos, qualquer que seja o
  resultado; então um intervalo ausente significa que o auditor não rodou: a página mostra cinza,
  nunca verde.
- Um **registro de testemunha** só aparece quando uma árvore cresceu; log parado não é problema.
- Um **registro horário** aparece toda hora, aconteça o que acontecer.
- Um **evento de mudança** (um serviço entrando num novo nível, um incidente aberto, atualizado ou
  resolvido, uma versão nova verificada, um achado da testemunha, o registro atrasado ou
  retomado) entra em `data/v1/cia/changes.json` e nos [feeds](#feeds-e-assinaturas) quando acontece;
  fora isso os feeds não são reescritos.
- **Nenhum workflow roda por commit.** O [`data.yml`](.github/workflows/data.yml) roda uma vez por
  hora e verifica todos os commits desde a última execução bem-sucedida, e toda segunda-feira o
  registro inteiro. O [`watchdog.yml`](.github/workflows/watchdog.yml) roda uma vez por hora e
  falha, para o GitHub avisar o responsável por e-mail, a menos que as duas portas da página de
  status respondam, o registro tenha menos de 20 minutos nas duas cópias e registros de amostra
  sejam idênticos byte a byte nas duas.

## Incidentes

Todo incidente tem **categorias**: `C` confidencialidade (dados foram expostos), `I` integridade
(algo mudou ou rodou que não devia) e `A` disponibilidade (um serviço ficou inutilizável). Um
incidente colore essas dimensões dos serviços que ele lista, do início até a resolução: `low` e
`medium` em amarelo, `high` e `critical` em vermelho, combinado com as medições pelo pior dos dois.
A confidencialidade é colorida só por incidentes: nada consegue medir um vazamento de fora.

- **Incidentes declarados** são arquivos Markdown em [`incidents/`](incidents), adicionados por pull
  request revisado. O [`incidents/README.md`](incidents/README.md) (em inglês) descreve o formato e o
  que cada campo faz com as cores; o [CONTRIBUTING.md](CONTRIBUTING.md) descreve o fluxo.
- **Incidentes automáticos** são abertos, atualizados e resolvidos pelo auditor, nunca por pessoas:
  um incidente de disponibilidade quando um serviço falha por 3 intervalos seguidos de cinco
  minutos, um de integridade por uma versão inválida, arquivos servidos diferentes do manifesto
  assinado ou um achado da testemunha. Um incidente de confidencialidade nunca é automático. Cada
  mudança é um registro imutável em `data/v1/cia/incidents/events/`, e o incidente aparece em
  `data/v1/cia/incidents.json` junto com os declarados. Para explicar um incidente automático,
  declare um com `relates: <id dele>` (um postmortem).

## Dado atrasado nunca é queda

Um atraso ou uma lacuna no registro aparece neutro e nunca conta como indisponibilidade: um intervalo
sem registro é *não medido* (`none`, uma marca cinza hachurada), e o fluxo de mudanças diz *registro
atrasado*, nunca *fora do ar*.

O auditor também se protege de falsos vermelhos. A cada execução ele faz uma sonda de controle a um
host fora da diagnos. Se a sonda de controle e todos os serviços falham na mesma execução, a rede do
próprio auditor caiu, não os serviços: a execução é uma **falha de ponto de observação** (*vantage*).
Todas as verificações de rede dela são gravadas como `none` com o código `vantage` (não `fail`),
nenhum incidente é aberto, e o fluxo de mudanças diz que a rede do auditor falhou. O
`tools/verify cia` rejeita um registro em que todos os serviços falharam enquanto a sonda de
controle falhava (ele devia ter sido gravado como falha de ponto de observação) e um registro cujas
verificações `vantage` são incoerentes.

O mesmo vale para cada testemunha em separado: uma testemunha cuja sonda de controle falhou não
mediu nada, e uma testemunha em silêncio não está medindo, o que deixa a região dela cinza e faz a
outra decidir. Nenhuma das duas conta como queda.

## Feeds e assinaturas

Cada evento de mudança é publicado em feeds (os últimos 100 eventos de cada), em RSS 2.0, Atom e JSON
Feed 1.1:

| Feed | O que traz |
| --- | --- |
| `feeds/all.rss`, `feeds/all.atom`, `feeds/all.json` | toda mudança |
| `feeds/<serviço>.rss`, `.atom`, `.json` para `frontend`, `vault`, `sign`, `status` | mudanças de um serviço |
| `feeds/incidents.rss`, `.atom`, `.json` | só incidentes, declarados e automáticos |

Eles são servidos em <https://status.diagnos.health/feeds/> e em
<https://imgexam-auditor-production.s3.fr-par.scw.cloud/feeds/>; ficam na página de status e no
bucket, não neste repositório. São uma conveniência para quem assina: o registro são os arquivos em
[`data/v1/`](data/v1). Cada feed declara um hub
[WebSub](https://www.w3.org/TR/websub/), então leitores que o suportam recebem a mudança na hora; os
outros consultam os arquivos estáticos.

- **Qualquer leitor de feeds:** adicione o endereço do feed.
- **Slack:** com o app RSS do Slack, `/feed subscribe https://status.diagnos.health/feeds/all.rss`.
- **Microsoft Teams:** o conector RSS, ou um fluxo do Workflows que roda quando um item do feed é
  publicado.
- **E-mail:** por um serviço de feed para e-mail, como Blogtrottr ou Feedrabbit. São terceiros que
  a diagnos não opera.

A diagnos não oferece assinaturas por e-mail nem por webhook.

## Confira você mesmo

Você precisa do Go 1.24+; para os carimbos horários, também de `openssl`, `jq` e `sha256sum`; para
as versões, também do [`cosign`](https://docs.sigstore.dev/cosign/system_config/installation/). Os
caminhos abaixo são ilustrativos, e todo comando, exceto a conferência de versão, também roda nos
dados de exemplo com `-root examples`.

```sh
git clone --depth 1 https://github.com/diagnos-tech/audit && cd audit

go run ./tools/verify cia                                                 # execuções, incidentes, visões
go run ./tools/verify release -cosign data/v1/cia/releases/vault/<digest> # uma versão, com cosign
go run ./tools/verify incidents incidents/*.md                            # declarações seguem o formato
go run ./tools/verify witness data/v1/audit/witness/2026/10/25/140503Z.json  # assinaturas + prova
go run ./tools/verify timestamp -openssl data/v1/timestamps/2026/10/25/14Z.json  # token horário + corrente
go run ./tools/verify all -openssl -cosign                                # tudo
```

Sem clonar, aponte o verificador para os arquivos no GitHub:

```sh
go run github.com/diagnos-tech/audit/tools/verify@latest witness \
  -root https://raw.githubusercontent.com/diagnos-tech/audit/develop/ \
  data/v1/audit/witness/2026/10/25/140503Z.json
```

O modo remoto serve para um registro que você nomeia (`witness`, `timestamp`, `finding`,
`consistency`, `release`). Ele não consegue listar arquivos, então `cia` e `all`, que leem o
registro inteiro, precisam de um clone.

O verificador depende só da biblioteca padrão do Go e de `golang.org/x/mod/sumdb/note`; as versões
são conferidas com o `cosign` que você instala, e toda conferência também pode ser feita à mão. O
[VERIFY.md](VERIFY.md) percorre cada passo, diz o que ele prova e explica como fixar chaves obtidas
por outro caminho, para que a conferência não dependa deste repositório.

## Organização do repositório

| Caminho | O que guarda | Quem escreve |
| --- | --- | --- |
| [`data/v1/cia/runs/AAAA/MM/DD/HHMMZ.json`](schemas/v1/cia-run.schema.json) | uma execução de cinco minutos: por serviço e dimensão, o nível e cada verificação com seu código, encadeada à execução anterior. O `cia-run/v1` é o registro de um só ponto de observação; o [`cia-run/v2`](schemas/v1/cia-run-v2.schema.json) traz a medição assinada de cada testemunha e o resultado combinado. Os dois ficam aqui, numa só corrente | auditor |
| [`data/v1/cia/incidents/AAAA/MM/DD/HHMMZ.json`](schemas/v1/cia-incidents.schema.json) | um snapshot dos incidentes declarados, gravado quando eles mudam | auditor |
| [`data/v1/cia/incidents/events/AAAA/MM/DD/<id>-<seq>.json`](schemas/v1/cia-incident-event.schema.json) | uma mudança de um incidente automático: aberto, atualizado ou resolvido | auditor |
| [`data/v1/cia/releases/<serviço>/<digest>/`](schemas/v1/cia-release.schema.json) | o veredito sobre uma versão e a evidência em que ele se baseou: manifesto, assinatura Sigstore, proveniência | auditor |
| [`data/v1/cia/days/AAAA/MM/DD.json`](schemas/v1/cia-day.schema.json) | uma visão: uma letra por intervalo de cinco minutos e por dimensão (incidentes incluídos), os trechos que não são verdes, a latência do dia | auditor |
| [`data/v1/cia/latest.json`](schemas/v1/cia-latest.schema.json), [`summary.json`](schemas/v1/cia-summary.schema.json), [`incidents.json`](schemas/v1/cia-incident-list.schema.json), [`changes.json`](schemas/v1/cia-changes.schema.json), [`changes-recent.json`](schemas/v1/cia-changes-recent.schema.json) | visões: o destaque, o resumo de 90 dias, os incidentes (declarados e automáticos) numa só lista, os últimos 500 eventos de mudança e os 30 mais novos deles | auditor |
| [`data/v1/sync.json`](schemas/v1/sync.schema.json) | até onde o diário privado do auditor já foi espelhado aqui | auditor |
| [`data/v1/<log>/witness/AAAA/MM/DD/HHMMSSZ.json`](schemas/v1/witness.schema.json) | um checkpoint cossinado e a prova de consistência desde o anterior | auditor |
| [`data/v1/<log>/findings/AAAA/MM/DD/HHMMSSZ.json`](schemas/v1/finding.schema.json) | evidência de mau comportamento do log (deve ficar vazio) | auditor |
| `data/v1/witnesses/latam/<log>/witness/…` e `…/findings/…` | os mesmos dois tipos de arquivo da segunda testemunha (América Latina), cossinados com a chave dela e encadeados por ela; os arquivos da testemunha primária continuam onde sempre estiveram | auditor |
| [`data/v1/timestamps/AAAA/MM/DD/HHZ.json`](schemas/v1/timestamp.schema.json) | o assunto da hora, o imprint e os dados do token | auditor |
| `data/v1/timestamps/AAAA/MM/DD/HHZ.tsr` | o `TimeStampResp` RFC 3161 como a autoridade respondeu (DER) | auditor |
| [`data/v1/index/AAAA/MM.json`](schemas/v1/index.schema.json) | lista leve dos registros de testemunha do mês | auditor |
| [`data/v1/latest.json`](schemas/v1/latest.schema.json), [`data/v1/state.json`](schemas/v1/state.schema.json) | o resumo da testemunha; o estado da própria testemunha | auditor |
| [`incidents/`](incidents) | incidentes declarados, um arquivo Markdown cada, e o modelo (incidentes automáticos nunca são arquivos aqui) | pessoas, por pull request |
| [`keys/`](keys) | chaves públicas dos logs e de cada testemunha (`witness/auditor.vkey`, e `witness/latam.vkey` quando for publicada); cadeias das autoridades de carimbo; [`signers.json`](keys/signers.json), a identidade de CI que deve assinar as versões de cada serviço | pessoas, por pull request |
| [`schemas/v1/`](schemas/v1) | JSON Schema 2020-12 de cada arquivo de dados | pessoas, por pull request |
| [`tools/verify`](tools/verify) e os pacotes que ele usa | o verificador independente | pessoas |
| [`tools/genexamples`](tools/genexamples), [`tools/ci`](tools/ci) | o gerador de exemplos e os scripts de CI | pessoas |
| [`examples/`](examples) | dados de exemplo assinados com chaves de exemplo; nunca registros reais | pessoas |
| [`.github/workflows/`](.github/workflows) | `check` (código e exemplos), `data` (o registro, a cada hora), `watchdog` (as portas e as cópias, a cada hora) | pessoas |
| `README.md`, `VERIFY.md`, `CONTRIBUTING.md`, `SECURITY.md`, `LICENSE`, `LICENSES/` | os documentos | pessoas |

**Registros são imutáveis; visões não.** Registros de execução, snapshots e eventos de incidentes,
evidência de versões, registros de testemunha, achados e registros horários nunca são reescritos: a
corrente horária fixa os bytes exatos deles, e o `data.yml` rejeita qualquer mudança em um deles.
Só as *visões* mudam: `latest.json`, `state.json`, `index/**`, `sync.json` e `cia/latest.json`,
`cia/summary.json`, `cia/incidents.json`, `cia/changes.json`, `cia/changes-recent.json` e `cia/days/**`. Cada visão é uma função pura dos
registros, e `tools/verify cia` recalcula todas e compara, então uma visão não pode dizer nada que
os registros não digam.

Todos os dados são JSON UTF-8 com fim de linha LF (o `.gitattributes` garante isso em qualquer
sistema, o que importa porque os registros são fixados pelo SHA-256). Os registros têm indentação de
dois espaços, para que as pessoas leiam no GitHub. As visões são escritas numa só linha, porque os
servidores que as entregam não comprimem e um vetor indentado custa uma linha por número; os leitores
aceitam as duas formas, e o verificador compara o que o arquivo diz, não como ele está diagramado. Datas
em RFC 3339 UTC com segundos; hashes de árvore em base64, como nos checkpoints; hashes de arquivo em
hex minúsculo, como o `sha256sum` imprime.

## Chaves e confiança

As chaves em [`keys/`](keys) permitem conferir os registros, os de cada testemunha inclusive. Conferir um registro com chaves lidas
do próprio repositório só mostra que o repositório é coerente consigo mesmo; para uma conferência
independente, compare-as com as chaves que a diagnos publica em outros lugares, ou guarde sua cópia e
passe-a com `-keys`. O [VERIFY.md](VERIFY.md#2-decide-which-keys-to-trust) diz onde procurar.
O arquivo de uma testemunha lista a chave atual e, depois de uma rotação, as chaves que ela substituiu,
de modo que todo registro já publicado continua a verificar
([keys/README.md](keys/README.md#rotating-a-witness-key)).
O [`keys/signers.json`](keys/signers.json) fixa, para cada serviço, o repositório GitHub (pelo id
numérico), o workflow e o branch cuja assinatura uma versão precisa ter.

## Desenvolvimento

Os dados são escritos pelo robô do auditor; pessoas mudam incidentes, documentos, schemas, chaves e o
verificador. Veja o [CONTRIBUTING.md](CONTRIBUTING.md) para os testes e as convenções. O formato de
cada arquivo é combinado com o auditor num contrato mantido no monorepo da diagnos; os schemas daqui
são a forma normativa dele.

## Licença

- **Código e documentação** (`tools/`, `schemas/`, os arquivos Markdown):
  [Apache License 2.0](LICENSE), como o [webtessera](https://github.com/diagnos-tech/webtessera).
  Copyright 2026 MedDeck LTDA.
- **Dados** (`data/`, `examples/data/`, `keys/`): licenciados sob a
  [CC BY-ND 4.0](LICENSES/CC-BY-ND-4.0.txt). Qualquer pessoa pode copiar, espelhar, arquivar e
  republicar o registro, inteiro ou em parte e para qualquer fim, desde que sem alteração e com o
  crédito "diagnos audit record, © 2026 MedDeck LTDA, CC BY-ND 4.0" e o link para este repositório.
  Cópias alteradas não podem ser compartilhadas: um registro editado deixa de ser o registro que as
  assinaturas cobrem. A licença também cobre os direitos sobre bases de dados que algumas
  jurisdições concedem.

## Segurança

Achou um jeito de fazer o verificador aceitar algo que deveria rejeitar, uma versão que o auditor
aceitou e o `cosign` rejeita, duas cópias do registro que discordam, ou um registro que não confere?
Veja o [SECURITY.md](SECURITY.md). Uma conferência que falha num registro real é exatamente o que
este repositório existe para revelar; por favor, relate.
