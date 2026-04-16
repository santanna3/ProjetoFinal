# Sistema de Autenticação Segura

Implementação completa dos requisitos 4.1:

| Critério | Implementação | Pts |
|---|---|---|
| Hash criptográfico + parametrizado | bcrypt cost 12 (~300ms/hash) | 4 |
| Salt criptográfico correto | `bcrypt.genSalt()` via `crypto.randomBytes` — único por usuário | 4 |
| 2FA funcional | TOTP RFC 6238, HMAC-SHA1, janela 30s, tolerância ±1 passo | 6 |
| Política de sessão/tentativas/bloqueio | 5 tentativas → bloqueio 15min, TTL 2h, idle 30min | 4 |

---

## Instalação

```bash
# 1. Instalar dependências
npm install

# 2. Iniciar servidor
npm start
# ou, com auto-reload:
npm run dev

# 3. Abrir no navegador
# http://localhost:3000
```

---

## Dependências

| Pacote | Função |
|---|---|
| `express` | Servidor HTTP |
| `bcrypt` | Hash bcrypt (cost 12) + salt automático |
| `speakeasy` | TOTP RFC 6238 / HMAC-SHA1 |
| `express-session` | Gerenciamento de sessão server-side |
| `express-rate-limit` | Rate limiting por IP |
| `cors` | Configuração CORS |

---

## Fluxo de autenticação

```
Cadastro
  └── bcrypt.genSalt(12) → salt único
  └── bcrypt.hash(senha, salt) → hash armazenado
  └── speakeasy.generateSecret() → secret TOTP

Login
  ├── Verifica bloqueio (tentativas < 5 e lockout expirado)
  ├── bcrypt.compare(senha, hash) → timing-safe
  ├── Senha errada → +1 tentativa → bloqueio se >= 5
  └── Senha correta:
       ├── 2FA inativo → cria sessão
       └── 2FA ativo   → aguarda código TOTP

TOTP
  └── speakeasy.totp.verify(secret, token, window=1)
  └── Código válido → cria sessão completa

Sessão
  └── Token 256 bits (crypto.randomBytes)
  └── TTL absoluto: 2h
  └── Idle timeout: 30min
  └── Cookie: httpOnly + SameSite=strict
```

---

## Rotas da API

| Método | Rota | Descrição |
|---|---|---|
| POST | `/api/register` | Cadastro com hash + secret TOTP |
| POST | `/api/login` | Login com verificação de hash e bloqueio |
| POST | `/api/login/totp` | Verificação do código TOTP |
| POST | `/api/totp/enable` | Ativa 2FA (requer sessão) |
| POST | `/api/totp/disable` | Desativa 2FA (requer senha) |
| GET  | `/api/me` | Dados da sessão atual |
| POST | `/api/logout` | Encerrar sessão |
| GET  | `/api/debug/users` | Estado interno (remover em produção!) |

---

## Pontos de segurança implementados

- **Hash bcrypt cost 12**: ~300ms por hash — inviabiliza força bruta mesmo com GPUs
- **Salt único por usuário**: gerado por CSPRNG — impede rainbow tables e ataques pré-computados
- **TOTP RFC 6238**: second factor independente do servidor — mesmo comprometimento do hash não permite acesso
- **Timing-safe compare**: `bcrypt.compare` usa HMAC interno — previne timing attacks
- **Resposta genérica**: erros de login não revelam se o e-mail existe (user enumeration)
- **Bloqueio progressivo**: 5 falhas = 15min bloqueado — mitiga ataques de força bruta online
- **Cookie httpOnly + SameSite**: previne XSS e CSRF
- **Rate limit por IP**: camada adicional contra ataques automatizados

---

## Aviso

`/api/debug/users` expõe dados internos e deve ser **removido em produção**.
Em produção, usar banco de dados real (PostgreSQL, MongoDB) e HTTPS obrigatório.
