# Registro da testemunha da diagnos

[![Check](https://github.com/diagnos-tech/audit/actions/workflows/check.yml/badge.svg)](https://github.com/diagnos-tech/audit/actions/workflows/check.yml)
[![Código: Apache-2.0](https://img.shields.io/badge/c%C3%B3digo-Apache--2.0-blue)](LICENSE)
[![Dados: CC0-1.0](https://img.shields.io/badge/dados-CC0--1.0-lightgrey)](LICENSES/CC0-1.0.txt)

**English:** [README.md](README.md) (a versão de referência; esta é a tradução)

Este repositório é o registro público e independente da **testemunha** que vigia os logs de
transparência da diagnos. A cada cinco minutos a testemunha lê o checkpoint assinado de cada log,
confere que o log só cresceu desde a última vez, cossina o que viu e grava o resultado aqui. A cada
hora, uma autoridade de carimbo de tempo externa (RFC 3161) data o registro inteiro.

**Página:** <https://diagnos-tech.github.io/audit/> · **Confira você mesmo:** [VERIFY.md](VERIFY.md)
(em inglês: os comandos são os mesmos em qualquer idioma)

A página é só uma conveniência. O registro são os arquivos em [`data/v1/`](data/v1), e tudo o que a
página afirma pode ser conferido a partir deles com ferramentas comuns, sem confiar na diagnos, na
testemunha nem na página.

## O que prova e o que não prova

| Prova | Não prova |
| --- | --- |
| **Só cresce.** Cada log só cresceu: todo checkpoint cossinado estende o anterior, por uma prova de consistência (RFC 9162) que qualquer pessoa recalcula, inclusive a partir dos tiles do próprio log. | **O que há nos logs.** As folhas são compromissos com sal (SHA-256 de um sal aleatório e do registro canônico). Este repositório nunca guarda folha, entrada nem dado pessoal. |
| **Uma só história.** O log mostrou à testemunha uma única história. Um segundo checkpoint conflitante, assinado pelo log, é evidência criptográfica e vira um achado público. | **Completude.** Que a diagnos registrou tudo o que deveria. A testemunha vê o log, não os sistemas que escrevem nele. |
| **Quando.** A cada hora uma autoridade independente assinou um hash que cobre o último estado das árvores e a hora anterior, então o passado não pode ser reescrito sem quebrar a corrente. | **A honestidade da testemunha por si só.** Por isso cada registro traz a assinatura do próprio log e uma prova que você refaz contra o log, e os carimbos horários vêm de terceiros. |

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
a cada 5 min   a testemunha lê os dois checkpoints ──► a árvore cresceu? ──► commit: registro(s) de testemunha
a cada hora    a testemunha carimba a hora          ──────────────────────► commit: registro horário + token
               sem crescimento e fora da hora       ──────────────────────► nenhum commit
```

- Um **registro de testemunha** só aparece quando uma árvore cresceu; log parado não é problema.
- Um **registro horário** aparece toda hora, aconteça o que acontecer; então um registro com mais de
  uma hora e meia significa que a testemunha parou de relatar. A página mostra isso como *atrasada*.
- A página relê `data/v1/latest.json` a cada quatro minutos. O GitHub Pages guarda os arquivos em
  cache por até dez minutos; as requisições da página levam um parâmetro por minuto para passar
  desse cache.

## Confira você mesmo

Você precisa do Go 1.24+ e, para os carimbos horários, também de `openssl`, `jq` e `sha256sum`. Os
caminhos abaixo são ilustrativos; o painel *Como conferir* da página preenche os reais, e todo
comando também roda nos dados de exemplo com `-root examples`.

```sh
git clone --depth 1 https://github.com/diagnos-tech/audit && cd audit

go run ./tools/verify witness data/v1/audit/witness/2026/10/25/140503Z.json      # assinaturas + prova
go run ./tools/verify consistency data/v1/audit/witness/2026/10/25/140503Z.json  # contra o log no ar
go run ./tools/verify timestamp -openssl data/v1/timestamps/2026/10/25/14Z.json  # token horário + corrente
go run ./tools/verify all -openssl                                               # tudo
```

Sem clonar, aponte o verificador para o site publicado:

```sh
go run github.com/diagnos-tech/audit/tools/verify@latest witness \
  -root https://diagnos-tech.github.io/audit/ data/v1/audit/witness/2026/10/25/140503Z.json
```

O verificador depende só da biblioteca padrão do Go e de `golang.org/x/mod/sumdb/note`, e toda
conferência também pode ser feita à mão. O [VERIFY.md](VERIFY.md) percorre cada passo, diz o que ele
prova e explica como fixar chaves obtidas por outro caminho, para que a conferência não dependa deste
repositório.

## Organização do repositório

| Caminho | O que guarda | Quem escreve |
| --- | --- | --- |
| [`data/v1/<log>/witness/AAAA/MM/DD/HHMMSSZ.json`](schemas/v1/witness.schema.json) | um checkpoint cossinado e a prova de consistência desde o anterior | testemunha |
| [`data/v1/<log>/findings/AAAA/MM/DD/HHMMSSZ.json`](schemas/v1/finding.schema.json) | evidência de mau comportamento do log (deve ficar vazio) | testemunha |
| [`data/v1/timestamps/AAAA/MM/DD/HHZ.json`](schemas/v1/timestamp.schema.json) | o assunto da hora, o imprint e os dados do token | testemunha |
| `data/v1/timestamps/AAAA/MM/DD/HHZ.tsr` | o `TimeStampResp` RFC 3161 como a autoridade respondeu (DER) | testemunha |
| [`data/v1/index/AAAA/MM.json`](schemas/v1/index.schema.json) | lista leve dos registros do mês, para a página | testemunha |
| [`data/v1/latest.json`](schemas/v1/latest.schema.json), [`data/v1/state.json`](schemas/v1/state.schema.json) | o resumo que a página lê primeiro; o estado da própria testemunha | testemunha |
| [`keys/`](keys) | chaves públicas dos logs e da testemunha; cadeias das autoridades de carimbo | pessoas |
| [`schemas/v1/`](schemas/v1) | JSON Schema 2020-12 de cada arquivo de dados | pessoas |
| [`tools/`](tools) | o verificador (`tools/verify`), o gerador de exemplos, scripts de CI | pessoas |
| [`index.html`](index.html), [`assets/`](assets) | a página: HTML, CSS e módulos ES nativos, sem build e sem dependências | pessoas |
| [`examples/`](examples) | dados de exemplo assinados com chaves de exemplo, para pré-visualizar a página; nunca registros reais | pessoas |

Registros datados são **imutáveis**: depois de commitados nunca são reescritos, porque a corrente
horária fixa os bytes exatos deles. Só `latest.json`, `state.json` e o índice do mês corrente mudam.
A CI rejeita qualquer mudança em registro passado.

Todos os dados são JSON UTF-8 com indentação de dois espaços e fim de linha LF (o `.gitattributes`
garante isso em qualquer sistema, o que importa porque os registros são fixados pelo SHA-256). Datas
em RFC 3339 UTC com segundos; hashes de árvore em base64, como nos checkpoints; hashes de arquivo em
hex minúsculo, como o `sha256sum` imprime.

## Chaves e confiança

As chaves em [`keys/`](keys) permitem conferir os registros. Conferir um registro com chaves lidas
do próprio repositório só mostra que o repositório é coerente consigo mesmo; para uma conferência
independente, compare-as com as chaves que a diagnos publica em outros lugares, ou guarde sua cópia e
passe-a com `-keys`. O [VERIFY.md](VERIFY.md#2-decide-which-keys-to-trust) diz onde procurar.

## Desenvolvimento

Os dados são escritos pelo robô da testemunha; pessoas mudam código e documentação. Veja o
[CONTRIBUTING.md](CONTRIBUTING.md) para a pré-visualização local (`python3 -m http.server` e depois
`?data=examples`), os testes e as convenções. O formato de cada arquivo é combinado com a testemunha
num contrato mantido no monorepo da diagnos; os schemas daqui são a forma normativa dele.

## Licença

- **Código e documentação** (`index.html`, `assets/`, `tools/`, `schemas/`, os arquivos Markdown):
  [Apache License 2.0](LICENSE), como o [webtessera](https://github.com/diagnos-tech/webtessera).
  Copyright 2026 MedDeck LTDA.
- **Dados** (`data/`, `examples/data/`, `keys/`): dedicados ao domínio público pela
  [CC0 1.0](LICENSES/CC0-1.0.txt). Um registro de integridade só serve se qualquer pessoa puder
  copiar, espelhar, arquivar e republicar sem pedir nem atribuir, e checkpoints e chaves são fatos; a
  CC0 remove toda condição, inclusive os direitos sobre bases de dados que algumas jurisdições
  concederiam.

## Segurança

Achou um jeito de fazer o verificador aceitar algo que deveria rejeitar, ou um registro que não
confere? Veja o [SECURITY.md](SECURITY.md). Uma conferência que falha num registro real é exatamente
o que este repositório existe para revelar; por favor, relate.
