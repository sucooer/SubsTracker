// @ts-check
/**
 * 通行密钥相关测试
 * 覆盖：注册/管理接口的鉴权、options 下发与 challenge 存取、验证失败路径
 *
 * 注意：真实注册/认证往返需要虚拟验证器，无法在 workerd 单测里跑；
 * 这里只覆盖路由、鉴权、challenge 存取和失败路径，真机验证靠部署后浏览器实测。
 */
import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
// @ts-ignore
import { env } from 'cloudflare:test';
import app from '../../src/app.js';
import { generateJWT } from '../../src/core/auth.js';

async function clearKv() {
  const list = await env.SUBSCRIPTIONS_KV.list();
  await Promise.all(list.keys.map((k) => env.SUBSCRIPTIONS_KV.delete(k.name)));
}

async function seedAdmin() {
  await env.SUBSCRIPTIONS_KV.put(
    'config',
    JSON.stringify({
      ADMIN_USERNAME: 'admin',
      ADMIN_PASSWORD: 'password',
      JWT_SECRET: 'test-secret-key'
    })
  );
}

async function loginCookie() {
  const token = await generateJWT('admin', 'test-secret-key');
  return 'token=' + token;
}

async function seedCredential() {
  await env.SUBSCRIPTIONS_KV.put(
    'passkeys',
    JSON.stringify([
      {
        id: 'dGVzdC1jcmVkZW50aWFsLWlk',
        publicKey: 'dGVzdC1wdWJsaWMta2V5',
        counter: 0,
        transports: ['usb'],
        name: '通行密钥 1',
        createdAt: '2026-11-23T00:00:00.000Z'
      }
    ])
  );
}

beforeEach(clearKv);
afterEach(() => {
  vi.useRealTimers();
});

describe('通行密钥注册接口鉴权', () => {
  it('未登录调 POST /api/passkey/register-options → 401', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/register-options',
      { method: 'POST' },
      env
    );
    expect(res.status).toBe(401);
  });

  it('未登录调 GET /api/passkey/credentials → 401', async () => {
    await seedAdmin();
    const res = await app.request('/api/passkey/credentials', {}, env);
    expect(res.status).toBe(401);
  });

  it('未登录调 POST /api/passkey/register-verify → 401', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/register-verify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      },
      env
    );
    expect(res.status).toBe(401);
  });
});

describe('POST /api/passkey/register-options', () => {
  it('已登录 → 200，返回 challenge 与 rp.id，并把 challenge 存进 KV', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/register-options',
      { method: 'POST', headers: { Cookie: await loginCookie() } },
      env
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(typeof body.options.challenge).toBe('string');
    expect(body.options.challenge.length).toBeGreaterThan(10);
    expect(body.options.rp.id).toBeTruthy();
    expect(body.options.user.name).toBe('admin');

    const stored = await env.SUBSCRIPTIONS_KV.get('passkey_challenge:register');
    expect(stored).toBeTruthy();
    expect(JSON.parse(stored).challenge).toBe(body.options.challenge);
  });
});

describe('POST /api/passkey/register-verify', () => {
  it('瞎编的 body → 400（challenge 对不上或解析失败）', async () => {
    await seedAdmin();
    // 先下发一次 options，让 KV 里有 challenge
    await app.request(
      '/api/passkey/register-options',
      { method: 'POST', headers: { Cookie: await loginCookie() } },
      env
    );
    const res = await app.request(
      '/api/passkey/register-verify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: await loginCookie() },
        body: JSON.stringify({ id: 'bogus', rawId: 'bogus', type: 'public-key', response: {} })
      },
      env
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.success).toBe(false);
  });

  it('没有 challenge 时直接调 verify → 400 提示会话过期', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/register-verify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: await loginCookie() },
        body: JSON.stringify({})
      },
      env
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(String(body.message)).toMatch(/过期/);
  });
});

describe('POST /api/passkey/login-options', () => {
  it('无已注册凭据 → success=false，提示先去注册', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/login-options',
      { method: 'POST' },
      env
    );
    const body = await res.json();
    expect(body.success).toBe(false);
    expect(String(body.message)).toMatch(/尚未注册/);
  });

  it('有已注册凭据 → 200，返回 challenge 与 allowCredentials，并把 challenge 存进 KV', async () => {
    await seedAdmin();
    await seedCredential();
    const res = await app.request(
      '/api/passkey/login-options',
      { method: 'POST' },
      env
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(typeof body.options.challenge).toBe('string');
    expect(body.options.allowCredentials).toHaveLength(1);
    expect(body.options.allowCredentials[0].id).toBe('dGVzdC1jcmVkZW50aWFsLWlk');

    const stored = await env.SUBSCRIPTIONS_KV.get('passkey_challenge:login');
    expect(stored).toBeTruthy();
    expect(JSON.parse(stored).challenge).toBe(body.options.challenge);
  });
});

describe('POST /api/passkey/login-verify', () => {
  it('没有 challenge 时直接调 verify → 400 提示会话过期', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/login-verify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      },
      env
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(String(body.message)).toMatch(/过期/);
  });

  it('challenge 在但凭据 id 未知 → 400', async () => {
    await seedAdmin();
    await seedCredential();
    await app.request('/api/passkey/login-options', { method: 'POST' }, env);
    const res = await app.request(
      '/api/passkey/login-verify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 'dW5rbm93bi1pZA', rawId: 'dW5rbm93bi1pZA', type: 'public-key', response: {} })
      },
      env
    );
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(String(body.message)).toMatch(/未知/);
  });
});

describe('GET /api/passkey/credentials', () => {
  it('已登录 → 返回列表，且不含 publicKey', async () => {
    await seedAdmin();
    await seedCredential();
    const res = await app.request(
      '/api/passkey/credentials',
      { headers: { Cookie: await loginCookie() } },
      env
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.credentials).toHaveLength(1);
    expect(body.credentials[0].name).toBe('通行密钥 1');
    expect(body.credentials[0].publicKey).toBeUndefined();
  });

  it('无凭据 → 空数组', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/credentials',
      { headers: { Cookie: await loginCookie() } },
      env
    );
    const body = await res.json();
    expect(body.credentials).toEqual([]);
  });
});

describe('DELETE /api/passkey/credentials/:id', () => {
  it('已登录删除存在的凭据 → 成功，列表变空', async () => {
    await seedAdmin();
    await seedCredential();
    const cookie = await loginCookie();
    const res = await app.request(
      '/api/passkey/credentials/dGVzdC1jcmVkZW50aWFsLWlk',
      { method: 'DELETE', headers: { Cookie: cookie } },
      env
    );
    expect(res.status).toBe(200);
    expect((await res.json()).success).toBe(true);

    const listRes = await app.request(
      '/api/passkey/credentials',
      { headers: { Cookie: cookie } },
      env
    );
    expect((await listRes.json()).credentials).toEqual([]);
  });

  it('删除不存在的凭据 → 404', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/credentials/bm90LWhlcmU',
      { method: 'DELETE', headers: { Cookie: await loginCookie() } },
      env
    );
    expect(res.status).toBe(404);
  });
});

describe('PATCH /api/passkey/credentials/:id（重命名）', () => {
  const url = '/api/passkey/credentials/dGVzdC1jcmVkZW50aWFsLWlk';

  it('未登录 → 401', async () => {
    await seedAdmin();
    await seedCredential();
    const res = await app.request(
      url,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: '新名字' })
      },
      env
    );
    expect(res.status).toBe(401);
  });

  it('已登录改名 → 200，列表里名字已变，公钥等字段不动', async () => {
    await seedAdmin();
    await seedCredential();
    const cookie = await loginCookie();
    const res = await app.request(
      url,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body: JSON.stringify({ name: '  我的 RS-Key  ' })
      },
      env
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
    expect(body.credential.name).toBe('我的 RS-Key'); // 首尾空白被去掉

    const listRes = await app.request(
      '/api/passkey/credentials',
      { headers: { Cookie: cookie } },
      env
    );
    const creds = (await listRes.json()).credentials;
    expect(creds).toHaveLength(1);
    expect(creds[0].name).toBe('我的 RS-Key');
    expect(creds[0].id).toBe('dGVzdC1jcmVkZW50aWFsLWlk');
  });

  it('改名不存在的凭据 → 404', async () => {
    await seedAdmin();
    const res = await app.request(
      '/api/passkey/credentials/bm90LWhlcmU',
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Cookie: await loginCookie() },
        body: JSON.stringify({ name: '新名字' })
      },
      env
    );
    expect(res.status).toBe(404);
  });

  it('名字为空 → 400', async () => {
    await seedAdmin();
    await seedCredential();
    const res = await app.request(
      url,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Cookie: await loginCookie() },
        body: JSON.stringify({ name: '   ' })
      },
      env
    );
    expect(res.status).toBe(400);
    expect(String((await res.json()).message)).toMatch(/不能为空/);
  });

  it('超长名字 → 截断到 64 字符后保存', async () => {
    await seedAdmin();
    await seedCredential();
    const cookie = await loginCookie();
    const res = await app.request(
      url,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', Cookie: cookie },
        body: JSON.stringify({ name: '名'.repeat(100) })
      },
      env
    );
    expect(res.status).toBe(200);
    expect((await res.json()).credential.name.length).toBe(64);
  });
});
