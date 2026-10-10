# Vulnera Action

Action oficial da Vulnera para executar os scanners de segurança no runner do GitHub Actions e enviar findings normalizados para a plataforma.

## O que ela faz

- executa Secrets, SCA, SAST e IaC;
- normaliza os resultados para o formato da Vulnera;
- envia findings e dependências usando um token OIDC de curta duração;
- não envia o relatório bruto do Gitleaks;
- limita artefatos grandes para evitar falhas de payload na API.

Os scanners são executados no runner do repositório. A Action não contém credenciais permanentes, tokens de instalação ou dados de clientes.

## Uso recomendado

A Vulnera gera este workflow automaticamente quando um repositório é conectado. Para uma integração manual:

```yaml
name: Vulnera Security

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  id-token: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Vulnera scan
        uses: eriklopess/vulnera-action@v1.0.0
        with:
          api-url: ${{ vars.VULNERA_API_URL }}
          repository-id: ${{ vars.VULNERA_REPOSITORY_ID }}
          scan-id: ${{ vars.VULNERA_SCAN_ID }}
          commit-sha: ${{ github.sha }}
          ref: ${{ github.ref }}
          allow-ingestion: 'true'
```

`api-url`, `repository-id` e `scan-id` são fornecidos pela Vulnera no workflow gerenciado. Não coloque tokens ou chaves privadas no YAML.

## Inputs

| Input | Obrigatório | Padrão | Descrição |
| --- | --- | --- | --- |
| `api-url` | sim | — | URL base da API Vulnera |
| `repository-id` | sim | — | ID do repositório cadastrado |
| `scan-id` | sim | — | ID da execução do scan |
| `commit-sha` | sim | — | SHA imutável analisado |
| `ref` | sim | — | Referência Git analisada |
| `scanners` | não | `secrets,sca,sast,iac` | Scanners separados por vírgula |
| `allow-ingestion` | não | `false` | Habilita o envio autenticado |
| `upload-artifacts` | não | `true` | Envia artefatos não sensíveis |

Scanners disponíveis: `secrets`, `sca`, `sast` e `iac`.

## Requisitos e permissões

- runner Linux x64, como `ubuntu-latest`;
- `actions/checkout` antes da Action;
- `permissions.id-token: write` para ingestão autenticada;
- `permissions.contents: read` para checkout do código.

Sem `allow-ingestion: 'true'`, a Action executa os scanners, mas encerra sem enviar os resultados. Isso é útil para testes do workflow.

## Segurança e privacidade

A autenticação usa OIDC do GitHub e tokens temporários. A API valida o repositório, o commit e a instalação ativa antes de aceitar os resultados.

O Gitleaks é tratado como dado sensível: seu relatório bruto nunca é salvo na Vulnera. Como os scanners são executados no runner do cliente, o proprietário desse runner pode observar processos e dependências. Para ocultar completamente os scanners, a execução precisa ser server-side na Vulnera.

## Publicação e versionamento

O workflow da plataforma referencia a tag imutável `v1.0.0`:

```yaml
uses: eriklopess/vulnera-action@v1.0.0
```

Ao publicar uma alteração, crie uma nova tag (`v1.0.1`, `v1.1.0`, etc.) e atualize `SCANNER_ACTION_REF` na API. Não mova uma tag já usada por clientes: isso mantém os scans reproduzíveis e permite rollout controlado.

## Problemas comuns

**OIDC não disponível** — confira `permissions.id-token: write`.

**Falha 401 no exchange** — confirme `api-url`, `repository-id`, `scan-id`, `commit-sha` e que o workflow foi disparado pelo repositório instalado na Vulnera.

**Falha 413 no artefato** — o artefato excedeu o limite da API; findings normalizados continuam sendo enviados.

**Scanner não suportado** — use Linux x64 e os nomes em minúsculas: `secrets`, `sca`, `sast`, `iac`.
