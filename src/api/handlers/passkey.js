// @ts-check
/**
 * 通行密钥（WebAuthn）登录
 *
 * 路由（由 src/api/router.js 在 JWT 门禁之前分发到这里）：
 *   POST   /api/passkey/register-options   注册：下发创建选项（需登录）
 *   POST   /api/passkey/register-verify    注册：验证并保存凭据（需登录）
 *   POST   /api/passkey/login-options      登录：下发认证选项（公开）
 *   POST   /api/passkey/login-verify       登录：验证断言，通过后发 JWT cookie（公开）
 *   GET    /api/passkey/credentials        列出已注册凭据（需登录，不返回公钥）
 *   DELETE /api/passkey/credentials/<id>   删除指定凭据（需登录）
 *
 * 存储（SUBSCRIPTIONS_KV）：
 *   passkeys                         凭据数组 [{ id, publicKey, counter, transports, name, createdAt }]
 *   passkey_challenge:register|login 最近一次下发的 challenge（5 分钟过期，一次性）
 *
 * 单管理员场景：同一时刻只有一个同类流程在跑，challenge 按类型固定 key 存储，
 * 新的 options 调用直接覆盖旧的。密码登录原样保留，作为丢密钥后的兜底。
 */
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from '@simplewebauthn/server';
import { generateJWT } from '../../core/auth.js';
import { getConfig } from '../../data/config.js';
import { getKVJson, putKVJson } from '../../data/kv.js';
import { getUserFromRequest } from './auth.js';

const CHALLENGE_TTL_SECONDS = 300; // challenge 有效期 5 分钟
const MAX_PASSKEY_ATTEMPTS = 5;
const PASSKEY_LOCKOUT_SECONDS = 300; // 5 分钟

function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders }
  });
}

function rpIdFor(request) {
  return new URL(request.url).hostname;
}

function originFor(request) {
  return new URL(request.url).origin;
}

function base64URLFromBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bufferFromBase64URL(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function getPasskeys(env) {
  const list = await getKVJson(env, 'passkeys', []);
  return Array.isArray(list) ? list : [];
}

async function savePasskeys(env, list) {
  await putKVJson(env, 'passkeys', list);
}

async function storeChallenge(env, challenge, type) {
  // 固定 key：新的 options 调用直接覆盖旧的 challenge
  await env.SUBSCRIPTIONS_KV.put(
    'passkey_challenge:' + type,
    JSON.stringify({ challenge, type }),
    { expirationTtl: CHALLENGE_TTL_SECONDS }
  );
}

async function takeChallenge(env, type) {
  // 一次性取用：读到就删除；取不到说明过期或根本没下发过
  const key = 'passkey_challenge:' + type;
  const data = await getKVJson(env, key, null);
  if (!data || data.challenge == null) return null;
  await env.SUBSCRIPTIONS_KV.delete(key);
  return data.challenge;
}

// ─────────────────────────────────────────────────────────────
// 登录限流（与密码登录同款逻辑、不同 key，避免互相锁死）
// ─────────────────────────────────────────────────────────────
function clientIp(request) {
  return request.headers.get('CF-Connecting-IP')
    || request.headers.get('X-Forwarded-For')
    || 'unknown';
}

async function checkPasskeyRateLimit(env, ip) {
  const raw = await env.SUBSCRIPTIONS_KV.get(`passkey_attempts:${ip}`);
  const attempts = raw ? parseInt(raw, 10) : 0;
  return attempts >= MAX_PASSKEY_ATTEMPTS;
}

async function recordPasskeyFailedAttempt(env, ip) {
  const key = `passkey_attempts:${ip}`;
  const raw = await env.SUBSCRIPTIONS_KV.get(key);
  const attempts = (raw ? parseInt(raw, 10) : 0) + 1;
  await env.SUBSCRIPTIONS_KV.put(key, String(attempts), { expirationTtl: PASSKEY_LOCKOUT_SECONDS });
  return attempts;
}

async function clearPasskeyAttempts(env, ip) {
  await env.SUBSCRIPTIONS_KV.delete(`passkey_attempts:${ip}`);
}

// ─────────────────────────────────────────────────────────────
// 注册
// ─────────────────────────────────────────────────────────────
async function handleRegisterOptions(request, env) {
  const { user, config } = await getUserFromRequest(request, env);
  if (!user) {
    return jsonResponse({ success: false, message: '未授权访问' }, 401);
  }

  const existing = await getPasskeys(env);
  // TextEncoder.encode() 返回 Uint8Array<ArrayBufferLike>，
  // 而 @simplewebauthn/server 要求 Uint8Array<ArrayBuffer>，需拷一份
  const userID = new Uint8Array(new TextEncoder().encode('admin'));
  const options = await generateRegistrationOptions({
    rpName: '订阅管理系统',
    rpID: rpIdFor(request),
    userName: config.ADMIN_USERNAME,
    userID,
    userDisplayName: config.ADMIN_USERNAME,
    attestationType: 'none',
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    excludeCredentials: existing.map((cred) => ({
      id: cred.id,
      transports: cred.transports || []
    }))
  });

  await storeChallenge(env, options.challenge, 'register');
  return jsonResponse({ success: true, options });
}

async function handleRegisterVerify(request, env) {
  const { user } = await getUserFromRequest(request, env);
  if (!user) {
    return jsonResponse({ success: false, message: '未授权访问' }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ success: false, message: '请求格式错误' }, 400);
  }

  const expectedChallenge = await takeChallenge(env, 'register');
  if (!expectedChallenge) {
    return jsonResponse({ success: false, message: '注册会话已过期，请重新开始注册' }, 400);
  }

  try {
    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: originFor(request),
      expectedRPID: rpIdFor(request),
      // userVerification 为 preferred：没设 PIN 的密钥不带 UV 标记，不能强制要求
      requireUserVerification: false
    });

    if (!verification.verified || !verification.registrationInfo) {
      return jsonResponse({ success: false, message: '注册验证失败' }, 400);
    }

    const credential = verification.registrationInfo.credential;
    const list = await getPasskeys(env);
    if (list.some((item) => item.id === credential.id)) {
      return jsonResponse({ success: false, message: '这个通行密钥已经注册过了' }, 400);
    }

    const entry = {
      id: credential.id,
      publicKey: base64URLFromBuffer(credential.publicKey),
      counter: credential.counter,
      transports: credential.transports || body?.response?.transports || [],
      name: '通行密钥 ' + (list.length + 1),
      createdAt: new Date().toISOString()
    };
    list.push(entry);
    await savePasskeys(env, list);

    return jsonResponse({
      success: true,
      credential: { id: entry.id, name: entry.name, createdAt: entry.createdAt }
    });
  } catch (error) {
    console.error('[通行密钥] 注册验证出错:', error);
    return jsonResponse({ success: false, message: '注册验证失败' }, 400);
  }
}

// ─────────────────────────────────────────────────────────────
// 登录
// ─────────────────────────────────────────────────────────────
async function handleLoginOptions(request, env) {
  const existing = await getPasskeys(env);
  if (existing.length === 0) {
    return jsonResponse({
      success: false,
      message: '尚未注册通行密钥，请先用密码登录后在系统配置里注册'
    });
  }

  const options = await generateAuthenticationOptions({
    rpID: rpIdFor(request),
    allowCredentials: existing.map((cred) => ({
      id: cred.id,
      transports: cred.transports || []
    })),
    userVerification: 'preferred'
  });

  await storeChallenge(env, options.challenge, 'login');
  return jsonResponse({ success: true, options });
}

async function handleLoginVerify(request, env) {
  const ip = clientIp(request);

  if (await checkPasskeyRateLimit(env, ip)) {
    return jsonResponse({ success: false, message: '登录尝试过多，请 5 分钟后再试' }, 429);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ success: false, message: '请求格式错误' }, 400);
  }

  const expectedChallenge = await takeChallenge(env, 'login');
  if (!expectedChallenge) {
    return jsonResponse({ success: false, message: '登录会话已过期，请重新开始登录' }, 400);
  }

  const list = await getPasskeys(env);
  const stored = list.find((item) => item.id === body?.id);
  if (!stored) {
    await recordPasskeyFailedAttempt(env, ip);
    return jsonResponse({ success: false, message: '未知的通行密钥' }, 400);
  }

  try {
    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: originFor(request),
      expectedRPID: rpIdFor(request),
      credential: {
        id: stored.id,
        publicKey: bufferFromBase64URL(stored.publicKey),
        counter: stored.counter,
        transports: stored.transports || []
      },
      requireUserVerification: false
    });

    if (!verification.verified) {
      await recordPasskeyFailedAttempt(env, ip);
      return jsonResponse({ success: false, message: '通行密钥验证失败' }, 400);
    }

    // 更新计数器（防重放），与密码登录一致发 JWT cookie
    stored.counter = verification.authenticationInfo.newCounter;
    await savePasskeys(env, list);
    await clearPasskeyAttempts(env, ip);

    const config = await getConfig(env);
    const token = await generateJWT(config.ADMIN_USERNAME, config.JWT_SECRET);
    return jsonResponse(
      { success: true },
      200,
      { 'Set-Cookie': 'token=' + token + '; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=86400' }
    );
  } catch (error) {
    console.error('[通行密钥] 登录验证出错:', error);
    await recordPasskeyFailedAttempt(env, ip);
    return jsonResponse({ success: false, message: '通行密钥验证失败' }, 400);
  }
}

// ─────────────────────────────────────────────────────────────
// 凭据管理（需登录）
// ─────────────────────────────────────────────────────────────
async function handleListCredentials(request, env) {
  const { user } = await getUserFromRequest(request, env);
  if (!user) {
    return jsonResponse({ success: false, message: '未授权访问' }, 401);
  }

  const list = await getPasskeys(env);
  return jsonResponse({
    success: true,
    credentials: list.map((item) => ({
      id: item.id,
      name: item.name,
      createdAt: item.createdAt,
      transports: item.transports || []
    }))
  });
}

async function handleDeleteCredential(request, env, id) {
  const { user } = await getUserFromRequest(request, env);
  if (!user) {
    return jsonResponse({ success: false, message: '未授权访问' }, 401);
  }

  const list = await getPasskeys(env);
  const next = list.filter((item) => item.id !== id);
  if (next.length === list.length) {
    return jsonResponse({ success: false, message: '未找到这个通行密钥' }, 404);
  }
  await savePasskeys(env, next);
  return jsonResponse({ success: true });
}

// ─────────────────────────────────────────────────────────────
// 总入口
// ─────────────────────────────────────────────────────────────
async function handlePasskeyRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname.slice(4); // 去掉 /api 前缀
  const method = request.method;

  if (path === '/passkey/register-options' && method === 'POST') {
    return handleRegisterOptions(request, env);
  }
  if (path === '/passkey/register-verify' && method === 'POST') {
    return handleRegisterVerify(request, env);
  }
  if (path === '/passkey/login-options' && method === 'POST') {
    return handleLoginOptions(request, env);
  }
  if (path === '/passkey/login-verify' && method === 'POST') {
    return handleLoginVerify(request, env);
  }
  if (path === '/passkey/credentials' && method === 'GET') {
    return handleListCredentials(request, env);
  }
  if (path.startsWith('/passkey/credentials/') && method === 'DELETE') {
    const id = decodeURIComponent(path.slice('/passkey/credentials/'.length));
    return handleDeleteCredential(request, env, id);
  }

  return jsonResponse({ success: false, message: '未找到请求的资源' }, 404);
}

export { handlePasskeyRequest };
