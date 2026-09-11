import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const source = await readFile(new URL('../server.mjs', import.meta.url), 'utf8');

function loadOkpaySigning(token) {
  const start = source.indexOf('function okpayFlattenParams');
  const end = source.indexOf('async function okpayRequest', start);
  assert.ok(start >= 0 && end > start, 'OKPay signing helpers must exist');
  const factory = new Function(
    'createHmac',
    'OKPAY_TOKEN',
    `${source.slice(start, end)}\nreturn { okpaySignBase, okpaySignature };`,
  );
  return factory(createHmac, token);
}

function loadTransferParser() {
  const currencyStart = source.indexOf('function currencyCents');
  const currencyEnd = source.indexOf('function telegramLedgerKeyboard', currencyStart);
  const parserStart = source.indexOf('function parseOkpayTransferCommand');
  const parserEnd = source.indexOf('function telegramOkpayTransferKeyboard', parserStart);
  assert.ok(currencyStart >= 0 && currencyEnd > currencyStart);
  assert.ok(parserStart >= 0 && parserEnd > parserStart);
  const factory = new Function(
    `${source.slice(currencyStart, currencyEnd)}\n` +
      `${source.slice(parserStart, parserEnd)}\n` +
      'return parseOkpayTransferCommand;',
  );
  return factory();
}

test('OKPay HMAC implementation matches all protocol vectors', () => {
  const signing = loadOkpaySigning('TESTtoken123456789abcdefghijABCD');
  assert.equal(
    signing.okpaySignature({
      id: 10001,
      amount: '100.5',
      coin: 'USDT',
      unique_id: 'ORDER-20260628-001',
      timestamp: 1782680000,
      nonce: 'a1b2c3d4e5',
    }),
    '7444ADFD8E4F4DA09D752DDF9345E0EE56DC25090FCFAF675DD042830E5E3F79',
  );
  assert.equal(
    signing.okpaySignature({
      status: 'success',
      code: 200,
      data: {
        order_id: 'abc123def456',
        unique_id: 'ORDER-20260628-001',
        pay_user_id: 123456789,
        amount: '100.5',
        coin: 'USDT',
        status: 1,
        type: 'deposit',
      },
      id: 10001,
    }),
    '64B09C8847849FA6921D8FFBDF8E406D4A8EA623E53970712350F61783403F7D',
  );
  assert.equal(
    signing.okpaySignature({
      id: 7,
      a: '0',
      b: 0,
      c: '',
      d: null,
      e: false,
      f: 'hello',
      nest: { x: '1', y: '2' },
    }),
    '8BC0AF979075038025DDD51B6F4A2E6CF3FF9B5B5371EB2268D303F89883E92A',
  );
});

test('transfer flow keeps authorization, confirmation and idempotency barriers', () => {
  assert.match(source, /telegramLedgerGroupAllowed\(chat, userId\)/);
  assert.match(source, /initiator_user_id\) !== userId/);
  assert.match(source, /status='awaiting_confirmation' AND expires_at>NOW\(\)/);
  assert.match(source, /unique_id TEXT NOT NULL UNIQUE/);
  assert.match(source, /WHERE id=\$1 AND status='awaiting_confirmation'/);
  assert.match(source, /Keep the same unique_id and query it later instead of retrying a debit/);
  assert.match(source, /status NOT IN \('succeeded','failed','cancelled','expired'\)/);
});

test('transfer command accepts only the renamed, bounded format', () => {
  const parse = loadTransferParser();
  assert.deepEqual(parse('转账 10.50 123456789'), {
    invalid: false,
    legacyName: false,
    amount: '10.5',
    toUserId: '123456789',
  });
  assert.equal(parse('普通聊天内容'), null);
  assert.equal(parse('转账 1 123456789').invalid, true);
  assert.equal(parse('转账 10.123 123456789').invalid, true);
  assert.equal(parse('转账 10 abc').invalid, true);
  assert.equal(parse('提现 10 123456789').legacyName, true);
});

test('signed success responses and withdrawal callbacks are verified', () => {
  assert.match(source, /if \(!body\.sign\)/);
  assert.match(source, /OKPay 成功响应缺少签名/);
  assert.match(source, /if \(data\.type === 'withdraw'\)/);
  assert.match(source, /applyOkpayTransferResult\(data, \{ fallbackMessage: true \}\)/);
  assert.match(source, /String\(data\.to_user_id \|\| ''\) !== String\(current\.to_user_id\)/);
  assert.match(source, /providerAmount !== expectedAmount/);
});

test('shop navigation uses a persistent menu and edits ordinary callback pages', () => {
  assert.match(source, /function telegramShopPersistentKeyboard/);
  assert.match(source, /is_persistent: true/);
  for (const label of ['购买卡密', '查询新增', '使用帮助', '联系客服', '机器人设置']) {
    assert.ok(source.includes(`{ text: '${label}' }`));
  }
  assert.match(source, /editTelegramShopCallbackMessage\(/);
  assert.match(source, /telegramShopOrderKeyboard\(result\.order, result\.link\?\.payUrl, config\.contacts\)/);
  assert.match(source, /firstContact[\s\S]*url: firstContact\.url/);
});
