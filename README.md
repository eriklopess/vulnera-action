# Vulnera Action

Este diretório é o pacote que deve ser publicado no repositório público
`eriklopess/vulnera-action`.

Ele deve conter somente o cliente de execução do GitHub Actions e não deve
conter chaves, tokens de instalação, credenciais ou dados de clientes.

## Publicação

1. Crie `eriklopess/vulnera-action` como repositório público.
2. Copie o conteúdo deste diretório para a raiz do novo repositório.
3. Publique uma tag imutável, por exemplo `v1.0.0`.
4. Configure `SCANNER_ACTION_REPOSITORY=eriklopess/vulnera-action` e
   `SCANNER_ACTION_REF=v1.0.0` na API.

O workflow instalado nos clientes referencia apenas essa Action. A autorização
dos resultados continua sendo feita pelo OIDC do GitHub e validada pela API
contra `repository`, `repository_id` e a instalação ativa do GitHub App.

## Limite de privacidade

Uma Action que executa scanners no runner do cliente não pode ocultar
completamente os binários ou comandos do proprietário desse runner. Para manter
os scanners proprietários fora do ambiente do cliente, eles precisam ser
migrados para execução server-side na Vulnera; esta Action deve então ficar
limitada a coletar metadados e enviar o contexto autorizado.
