// Tests for the invite-pipe shape helpers (invite pipeline, slice 1).
// Run from the repo root with: node test-pipe.js
//
// Pure-helper tests only, matching the repo convention. The endpoint
// handlers (POST /pipe, /pipe/:code/redeem, GET /pipe/:code/owner,
// POST /pipe/:code/close) are validated end-to-end against a live
// testbed instance, not in unit tests.

const {
  validPipeCode,
  validPipeName,
  validatePipeCreateShape,
  validatePipeRedeemShape,
  generateOwnerCode,
} = require('./server.js');

let passed = 0;
let failed = 0;

function check(label, ok, detail) {
  if (ok) {
    console.log('  PASS  ' + label);
    passed += 1;
  } else {
    console.log('  FAIL  ' + label + (detail ? '  (' + detail + ')' : ''));
    failed += 1;
  }
}

const GOOD_PIPE = 'ACDEFGHJKM'; // 10 chars, all from the language-proof charset

function baseCreate(overrides = {}) {
  return {
    pipe_code: GOOD_PIPE,
    fingerprint: 'f'.repeat(16),
    public_key: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    name: 'Michael',
    max_redemptions: 1,
    ...overrides,
  };
}

function baseRedeem(overrides = {}) {
  return {
    redeemer_code: 'ACDE',
    fingerprint: 'g'.repeat(16),
    public_key: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    name: 'Visitor',
    ...overrides,
  };
}

console.log('');
console.log('validPipeCode');

check('accepts 10-char language-proof code', validPipeCode(GOOD_PIPE) === true);
check('rejects null', validPipeCode(null) === false);
check('rejects number', validPipeCode(1234567890) === false);
check('rejects 9 chars', validPipeCode('ACDEFGHJK') === false);
check('rejects 11 chars', validPipeCode('ACDEFGHJKMA') === false);
check('rejects lowercase', validPipeCode('acdefghjkm') === false);
check('rejects excluded letter O', validPipeCode('OCDEFGHJKM') === false);
check('rejects excluded letter I', validPipeCode('ICDEFGHJKM') === false);
check('rejects excluded letter L', validPipeCode('LCDEFGHJKM') === false);
check('rejects excluded letter S', validPipeCode('SCDEFGHJKM') === false);
check('rejects excluded letter B', validPipeCode('BCDEFGHJKM') === false);
check('rejects digits', validPipeCode('ACDEFGHJK1') === false);
check('rejects session-length code', validPipeCode('ACDE') === false);

console.log('');
console.log('validPipeName');

check('accepts undefined', validPipeName(undefined) === true);
check('accepts null', validPipeName(null) === true);
check('accepts empty string', validPipeName('') === true);
check('accepts normal name', validPipeName('Michael') === true);
check('accepts 80 chars', validPipeName('a'.repeat(80)) === true);
check('rejects 81 chars', validPipeName('a'.repeat(81)) === false);
check('rejects number', validPipeName(42) === false);
check('rejects object', validPipeName({}) === false);

console.log('');
console.log('validatePipeCreateShape');

check('accepts valid create body', validatePipeCreateShape(baseCreate()) === null);
check('accepts absent name', validatePipeCreateShape(baseCreate({ name: undefined })) === null);
check('accepts absent cap (defaults at handler)', validatePipeCreateShape(baseCreate({ max_redemptions: undefined })) === null);
check('accepts cap 0 (uncapped room)', validatePipeCreateShape(baseCreate({ max_redemptions: 0 })) === null);
check('accepts cap 500', validatePipeCreateShape(baseCreate({ max_redemptions: 500 })) === null);
check('rejects null body', validatePipeCreateShape(null) !== null);
check('rejects non-object body', validatePipeCreateShape('hi') !== null);
check('rejects bad pipe_code', validatePipeCreateShape(baseCreate({ pipe_code: 'SHORT' })) !== null);
check('rejects missing fingerprint', validatePipeCreateShape(baseCreate({ fingerprint: '' })) !== null);
check('rejects missing public_key', validatePipeCreateShape(baseCreate({ public_key: undefined })) !== null);
check('rejects oversize name', validatePipeCreateShape(baseCreate({ name: 'a'.repeat(81) })) !== null);
check('rejects negative cap', validatePipeCreateShape(baseCreate({ max_redemptions: -1 })) !== null);
check('rejects fractional cap', validatePipeCreateShape(baseCreate({ max_redemptions: 1.5 })) !== null);
check('rejects cap over 500', validatePipeCreateShape(baseCreate({ max_redemptions: 501 })) !== null);
check('rejects string cap', validatePipeCreateShape(baseCreate({ max_redemptions: '1' })) !== null);

console.log('');
console.log('validatePipeRedeemShape');

check('accepts valid redeem body', validatePipeRedeemShape(baseRedeem()) === null);
check('accepts absent name', validatePipeRedeemShape(baseRedeem({ name: undefined })) === null);
check('rejects null body', validatePipeRedeemShape(null) !== null);
check('rejects missing redeemer_code', validatePipeRedeemShape(baseRedeem({ redeemer_code: undefined })) !== null);
check('rejects 3-char redeemer_code', validatePipeRedeemShape(baseRedeem({ redeemer_code: 'ACD' })) !== null);
check('rejects 5-char redeemer_code', validatePipeRedeemShape(baseRedeem({ redeemer_code: 'ACDEF' })) !== null);
check('rejects lowercase redeemer_code', validatePipeRedeemShape(baseRedeem({ redeemer_code: 'acde' })) !== null);
check('rejects missing fingerprint', validatePipeRedeemShape(baseRedeem({ fingerprint: '' })) !== null);
check('rejects missing public_key', validatePipeRedeemShape(baseRedeem({ public_key: null })) !== null);
check('rejects oversize name', validatePipeRedeemShape(baseRedeem({ name: 'a'.repeat(81) })) !== null);

console.log('');
console.log('generateOwnerCode');

const codes = new Set();
let allValid = true;
for (let i = 0; i < 200; i++) {
  const c = generateOwnerCode();
  if (!/^[ACDEFGHJKMNPQRTUVWXYZ]{4}$/.test(c)) allValid = false;
  codes.add(c);
}
check('always 4 chars from the language-proof charset (200 draws)', allValid);
check('draws are not constant (200 draws yield > 50 distinct codes)', codes.size > 50, 'distinct=' + codes.size);

console.log('');
console.log('Results: ' + passed + ' passed, ' + failed + ' failed');
process.exit(failed > 0 ? 1 : 0);
