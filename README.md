# Veltrix Staff + Tickets — V31.44

Atualização compatível com o portal que já está rodando no Render/Neon. Mantém o visual das transcrições e adiciona `/staff` protegido por login Discord.

## Recursos desta versão

- `/t/<token>`: transcrição HTML privada como antes (sem mudança de funcionamento).
- `/staff`: login via Discord OAuth2 e seleção de servidores em que o usuário possui **Gerenciar Servidor**.
- `/staff/g/<id>`: configurar **um canal privado por grupo de logs**, inclusive Chat e Banimentos/Punições.
- Ativar/desativar o registro global e a cópia opcional de textos editados/apagados.
- Bot checa novamente as permissões do operador e do canal antes de aplicar alterações.
- Variações dos logs individuais continuam disponíveis no Discord via `.logpainel`.

**Escopo atual do dashboard web:** Logs ULTRA. Os painéis de tickets, Anti-Raid e outras configurações da staff podem ser integrados em atualizações posteriores. Não há opção de administrar esses outros módulos por esta versão do site.

## Atualizar o GitHub e o Render

Envie o **conteúdo extraído** do ZIP para a raiz do repositório `veltrix-tickets`: `app.py`, `staff_web.py`, `requirements.txt`, `tests/` e o README. Sobrescreva o `app.py` atual; não apague os dados Neon. O Render deve fazer deploy do último commit.

Start Command continua:

```sh
gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120
```

Build Command continua:

```sh
pip install -r requirements.txt
```

Variáveis existentes **mantidas** no Render:

```env
DATABASE_URL=CONEXAO_DO_NEON
PUBLIC_BASE_URL=https://veltrix-tickets.onrender.com
VELTRIX_PORTAL_API_KEY=MESMA_CHAVE_DO_BOT
```

Adicione **somente ao Render**:

```env
DISCORD_CLIENT_ID=CLIENT_ID_DO_APLICATIVO_VELTRIX
DISCORD_CLIENT_SECRET=CLIENT_SECRET_DO_APLICATIVO_VELTRIX
```

No [Discord Developer Portal](https://discord.com/developers/applications), abra o aplicativo da Veltrix → **OAuth2** → **Redirects** e cadastre exatamente:

```text
https://veltrix-tickets.onrender.com/staff/callback
```

Guarde o `DISCORD_CLIENT_SECRET` apenas nas variáveis privadas do Render. Não o publique no GitHub, no chat ou no KataBump. Se o Render atribuiu um domínio diferente, use esse domínio real na configuração e no redirect.

## Atualizar o bot no KataBump

Extraia `Veltrix_V31_44_LOGS_GRUPOS_E_STAFF.zip` e substitua apenas `veltrix_modules.zip` na hospedagem. Preserve `main.py`, `.env` e a pasta `data` (incluindo SQLite). Não precisa de novas bibliotecas no bot para este recurso.

O bot usa as **mesmas variáveis já configuradas para as transcrições**:

```env
VELTRIX_TRANSCRIPT_REMOTE_URL=https://veltrix-tickets.onrender.com
VELTRIX_TRANSCRIPT_API_KEY=MESMA_CHAVE_SECRETA_DO_RENDER
```

Depois de reiniciar, aguarde a primeira sincronização (normalmente até ~1 minuto, mais o tempo de acordar o Render Free); o painel mostrará o servidor quando a Veltrix registrar seus canais privados. Os comandos continuam disponíveis caso o portal esteja fora do ar.

- `.loggrupos`: abre painel Discord para roteamento em massa.
- `.loggrupo chat #logs-chat`: aplica a todos os eventos de Chat.
- `.loggrupo banimentos #logs-punicoes`: aplica a banimentos, desbanimentos, expulsões e timeout.
- `.loggrupo todos #logs-staff`: aplica todos os logs a um só canal.
- `.logsativar on`: liga os logs.
- `.logsconteudo on`: habilita coleta temporária de conteúdo disponível (desligado por padrão).
- `.painelstaff`: exibe o link do painel web.

## Privacidade e limites

- Os destinos precisam ser canais privados, ocultos para `@everyone`, e acessíveis à Veltrix.
- Login web expira em 1 hora; cada mudança é revisada de novo pelo bot.
- Ao escolher um grupo, os **destinos individuais anteriores desse grupo são apagados**. A ativação/desativação dos eventos individuais continua preservada.
- O painel web atual administra apenas os logs. Ele não recebe o token do bot nem cópias de mensagens.
- O conteúdo apagado/editado só está disponível enquanto houver cache e quando ativado expressamente; não recupera mensagens anteriores ou não vistas pelo bot.
- Render Free e Neon podem demorar a responder após inatividade; a sincronização pode sofrer atraso.

## Testes

```sh
python -m unittest discover -s tests -v
```

O site foi testado localmente com simulações. Ainda precisa de teste real de OAuth, Neon e Discord no seu ambiente.
