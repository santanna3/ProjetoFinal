/**
 * Sistema de Autenticação Segura
 * 
 * Implementa:
 *  - Hash bcrypt (cost 12) + salt criptográfico por usuário
 *  - 2FA via TOTP (RFC 6238 / HMAC-SHA1)
 *  - Política de sessão: TTL, idle timeout, tentativas e bloqueio
 */

const express = require('express');
const bcrypt = require('bcrypt');
const speakeasy = require('speakeasy');
const crypto = require('crypto');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(__dirname));
app.use(cors({ origin: true, credentials: true }));

// ─────────────────────────────────────────────
// Configuração de política
// ─────────────────────────────────────────────
const POLICY = {
  BCRYPT_COST: 12,              // custo computacional do hash
  MAX_ATTEMPTS: 5,              // tentativas antes do bloqueio
  LOCK_DURATION_MS: 15 * 60 * 1000,  // 15 minutos de bloqueio
  SESSION_TTL_MS: 2 * 60 * 60 * 1000, // 2 horas de TTL de sessão
  IDLE_TIMEOUT_MS: 30 * 60 * 1000,    // 30 min idle timeout
  TOTP_WINDOW: 1,               // tolerância ±1 passo (30s cada)
  TOTP_STEP: 30,                // segundos por passo TOTP
};

// ─────────────────────────────────────────────
// "Banco de dados" em memória
// ─────────────────────────────────────────────
const users = new Map();       // email → { hash, salt, totpSecret, totpEnabled, ... }
const sessions = new Map();    // sessionId → { userId, createdAt, lastActivity, expiresAt }
const loginAttempts = new Map(); // email → { count, lockedUntil }

// ─────────────────────────────────────────────
// Rate limit global (camada adicional de proteção)
// ─────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Muitas requisições. Tente novamente em 15 minutos.' },
});

// ─────────────────────────────────────────────
// Middleware de sessão
// ─────────────────────────────────────────────
app.use(session({
  secret: crypto.randomBytes(64).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,    // previne acesso via JavaScript (XSS)
    secure: false,     // true em produção com HTTPS
    sameSite: 'strict',
    maxAge: POLICY.SESSION_TTL_MS,
  },
}));

// ─────────────────────────────────────────────
// Funções auxiliares
// ─────────────────────────────────────────────

/** Gera um token de sessão seguro */
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

/** Verifica se uma conta está bloqueada */
function isLocked(email) {
  const att = loginAttempts.get(email);
  if (!att) return false;
  if (att.lockedUntil && Date.now() < att.lockedUntil) return true;
  // Desbloqueia automaticamente após o tempo
  if (att.lockedUntil && Date.now() >= att.lockedUntil) {
    att.count = 0;
    att.lockedUntil = null;
  }
  return false;
}

/** Registra uma tentativa de login malsucedida */
function recordFailedAttempt(email) {
  const att = loginAttempts.get(email) || { count: 0, lockedUntil: null };
  att.count += 1;
  if (att.count >= POLICY.MAX_ATTEMPTS) {
    att.lockedUntil = Date.now() + POLICY.LOCK_DURATION_MS;
  }
  loginAttempts.set(email, att);
  return att;
}

/** Reseta tentativas após login bem-sucedido */
function resetAttempts(email) {
  loginAttempts.set(email, { count: 0, lockedUntil: null });
}

/** Cria e armazena uma sessão autenticada */
function createSession(req, email) {
  const token = generateSessionToken();
  const now = Date.now();
  sessions.set(token, {
    email,
    createdAt: now,
    lastActivity: now,
    expiresAt: now + POLICY.SESSION_TTL_MS,
  });
  req.session.token = token;
  req.session.email = email;
  return token;
}

/** Middleware: verifica sessão válida + idle timeout */
function requireAuth(req, res, next) {
  const token = req.session?.token;
  if (!token) return res.status(401).json({ error: 'Não autenticado.' });

  const sess = sessions.get(token);
  if (!sess) return res.status(401).json({ error: 'Sessão inválida.' });

  const now = Date.now();

  // Verifica TTL absoluto
  if (now > sess.expiresAt) {
    sessions.delete(token);
    req.session.destroy();
    return res.status(401).json({ error: 'Sessão expirada.' });
  }

  // Verifica idle timeout
  if (now - sess.lastActivity > POLICY.IDLE_TIMEOUT_MS) {
    sessions.delete(token);
    req.session.destroy();
    return res.status(401).json({ error: 'Sessão encerrada por inatividade.' });
  }

  // Atualiza última atividade
  sess.lastActivity = now;
  req.user = { email: sess.email };
  next();
}

// ─────────────────────────────────────────────
// ROTAS
// ─────────────────────────────────────────────

/**
 * POST /api/register
 * Cria usuário com:
 *   1. Validação de senha
 *   2. Geração de salt criptográfico (via bcrypt.genSalt)
 *   3. Hash bcrypt com cost 12
 *   4. Geração de secret TOTP
 */
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });

  if (password.length < 8)
    return res.status(400).json({ error: 'Senha muito curta. Mínimo de 8 caracteres.' });

  if (users.has(email))
    return res.status(409).json({ error: 'E-mail já cadastrado.' });

  // 4.1 – Hash criptográfico + salt
  // bcrypt.hash() gera internamente um salt único e seguro (via crypto.randomBytes)
  // cost 12 ≈ ~300ms por hash — dificulta ataques de força bruta e rainbow tables
  const salt = await bcrypt.genSalt(POLICY.BCRYPT_COST);
  const hash = await bcrypt.hash(password, salt);

  // 4.1 – 2FA: gera secret TOTP único por usuário
  const totpData = speakeasy.generateSecret({
    name: `AuthSystem (${email})`,
    length: 20,
  });

  users.set(email, {
    email,
    hash,
    salt,           // armazenado para auditoria; bcrypt já embute o salt no hash
    totpSecret: totpData.base32,
    totpOtpAuthUrl: totpData.otpauth_url,
    totpEnabled: false,
    createdAt: new Date().toISOString(),
  });

  loginAttempts.set(email, { count: 0, lockedUntil: null });

  // Mantem o fluxo da UI: apos cadastrar, o usuario ja pode ativar 2FA
  createSession(req, email);

  res.status(201).json({
    message: 'Usuário criado com sucesso.',
    email,
    totpSecret: totpData.base32,
    totpOtpAuthUrl: totpData.otpauth_url,
    info: 'Escaneie o QR code com um app autenticador (Google Authenticator, Authy) para ativar o 2FA.',
  });
});

/**
 * POST /api/login
 * Fluxo:
 *   1. Verifica bloqueio ativo
 *   2. Busca usuário e compara hash (timing-safe via bcrypt)
 *   3. Registra falha ou reseta tentativas
 *   4. Se 2FA ativo → retorna pendente de TOTP
 *   5. Caso contrário → cria sessão
 */
app.post('/api/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });

  // 4.1 – Política de bloqueio
  if (isLocked(email)) {
    const att = loginAttempts.get(email);
    const remaining = Math.ceil((att.lockedUntil - Date.now()) / 60000);
    return res.status(423).json({
      error: `Conta bloqueada. Tente novamente em ${remaining} minuto(s).`,
      lockedUntil: att.lockedUntil,
    });
  }

  const user = users.get(email);
  if (!user) {
    // Resposta genérica para não revelar se o e-mail existe (user enumeration)
    return res.status(401).json({ error: 'Credenciais inválidas.' });
  }

  // 4.1 – Comparação timing-safe (bcrypt.compare usa hmac interno)
  const valid = await bcrypt.compare(password, user.hash);

  if (!valid) {
    const att = recordFailedAttempt(email);
    const remaining = POLICY.MAX_ATTEMPTS - att.count;
    if (att.lockedUntil) {
      return res.status(423).json({ error: `Senha incorreta. Conta bloqueada por ${POLICY.LOCK_DURATION_MS / 60000} minutos.` });
    }
    return res.status(401).json({ error: `Credenciais inválidas. ${remaining} tentativa(s) restante(s).` });
  }

  // Credenciais corretas — reseta tentativas
  resetAttempts(email);

  // 4.1 – 2FA
  if (user.totpEnabled) {
    // Armazena temporariamente que a senha foi validada (aguarda TOTP)
    req.session.pendingEmail = email;
    req.session.pendingExpires = Date.now() + 5 * 60 * 1000; // 5 min para inserir o código
    return res.status(200).json({ requires2FA: true, message: 'Insira o código TOTP.' });
  }

  // Cria sessão sem 2FA
  createSession(req, email);
  res.json({ message: 'Login realizado com sucesso.', email });
});

/**
 * POST /api/login/totp
 * Valida o código TOTP após autenticação de senha
 */
app.post('/api/login/totp', (req, res) => {
  const { token } = req.body;

  const email = req.session?.pendingEmail;
  const expires = req.session?.pendingExpires;

  if (!email || !expires || Date.now() > expires) {
    return res.status(401).json({ error: 'Sessão de 2FA expirada. Faça login novamente.' });
  }

  const user = users.get(email);
  if (!user) return res.status(401).json({ error: 'Usuário não encontrado.' });

  // Verifica o código TOTP (±1 passo = tolerância de 30s para drift de relógio)
  const verified = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token,
    window: POLICY.TOTP_WINDOW,
    step: POLICY.TOTP_STEP,
  });

  if (!verified) {
    return res.status(401).json({ error: 'Código TOTP inválido ou expirado.' });
  }

  // Limpa estado pendente e cria sessão completa
  delete req.session.pendingEmail;
  delete req.session.pendingExpires;
  createSession(req, email);

  res.json({ message: 'Autenticação 2FA bem-sucedida.', email });
});

/**
 * POST /api/totp/enable
 * Ativa o 2FA para o usuário após verificar o primeiro código
 */
app.post('/api/totp/enable', requireAuth, (req, res) => {
  const { token } = req.body;
  const user = users.get(req.user.email);

  const verified = speakeasy.totp.verify({
    secret: user.totpSecret,
    encoding: 'base32',
    token,
    window: POLICY.TOTP_WINDOW,
  });

  if (!verified) return res.status(401).json({ error: 'Código inválido. 2FA não ativado.' });

  user.totpEnabled = true;
  res.json({ message: '2FA ativado com sucesso.' });
});

/**
 * POST /api/totp/disable
 * Desativa 2FA (requer senha atual)
 */
app.post('/api/totp/disable', requireAuth, async (req, res) => {
  const { password } = req.body;
  const user = users.get(req.user.email);

  const valid = await bcrypt.compare(password, user.hash);
  if (!valid) return res.status(401).json({ error: 'Senha incorreta.' });

  user.totpEnabled = false;
  res.json({ message: '2FA desativado.' });
});

/**
 * POST /api/logout
 * Encerra a sessão do servidor e do cookie
 */
app.post('/api/logout', requireAuth, (req, res) => {
  const token = req.session.token;
  if (token) sessions.delete(token);
  req.session.destroy();
  res.json({ message: 'Logout realizado.' });
});

/**
 * GET /api/me
 * Rota protegida — retorna dados da sessão atual
 */
app.get('/api/me', requireAuth, (req, res) => {
  const user = users.get(req.user.email);
  const sess = sessions.get(req.session.token);
  res.json({
    email: req.user.email,
    totpEnabled: user.totpEnabled,
    sessionCreatedAt: sess.createdAt,
    sessionExpiresAt: sess.expiresAt,
  });
});

/**
 * GET /api/debug/users
 * Mostra estado interno (remover em produção!)
 */
app.get('/api/debug/users', (req, res) => {
  const result = [];
  for (const [email, u] of users.entries()) {
    const att = loginAttempts.get(email) || {};
    result.push({
      email,
      salt: u.salt,
      hashPreview: u.hash.substring(0, 40) + '...',
      totpEnabled: u.totpEnabled,
      totpSecret: u.totpSecret,
      attempts: att.count || 0,
      lockedUntil: att.lockedUntil,
      createdAt: u.createdAt,
    });
  }
  res.json({ users: result, activeSessions: sessions.size, policy: POLICY });
});

// ─────────────────────────────────────────────
// Start
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🔒 Servidor de autenticação rodando em http://localhost:${PORT}`);
  console.log(`   Bcrypt cost: ${POLICY.BCRYPT_COST} | Max tentativas: ${POLICY.MAX_ATTEMPTS} | Bloqueio: ${POLICY.LOCK_DURATION_MS / 60000}min\n`);
});
