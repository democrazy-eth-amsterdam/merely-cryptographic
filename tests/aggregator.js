const BigInteger = require("jsbn").BigInteger;
const crypto = require("crypto");

function random(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
// PUBLIC PARAMETERS
var p = new BigInteger("142950481577612897377251366207350601085193026787763232208511322259955075211826388565191137969675785957228922178875744018870301928203434246727650650452188476517559379655516949015006180412307375960073546778478575555767086902406147563214485604901264760329721957156402926704404814419844454185694597535438114709207");
var q = new BigInteger("71475240788806448688625683103675300542596513393881616104255661129977537605913194282595568984837892978614461089437872009435150964101717123363825325226094238258779689827758474507503090206153687980036773389239287777883543451203073781607242802450632380164860978578201463352202407209922227092847298767719057354057");
var q_prev = q.subtract(new BigInteger("1"));
var g = new BigInteger("5");

// ==========================================
// private parameters, just for testing!
var secret_key = new BigInteger("1890613122308636483214615263089879914353133622183312356168367195770925616569283503768300091983802355020338489773460540926699954929058171678498009622408788252");
function generate_pk(sk) {
  return g.modPow(sk, p);
}
// ==========================================

async function getRandomBigIntAsync(min, max) {
  const range = max.subtract(min).subtract(BigInteger.ONE);

  let bi;
  do {
    // Generate random bytes with the length of the range
    const buf = await crypto.randomBytes(Math.ceil(range.bitLength() / 8));

    // Offset the result by the minimum value
    bi = new BigInteger(buf.toString("hex"), 16).add(min);
  } while (bi.compareTo(max) >= 0);

  // Return the result which satisfies the given range
  return bi;
}

var pk = generate_pk(secret_key);

function customHash(values) {
  let h = new BigInteger("0");
  for (let i = 0; i < values.length; i++) {
    h = h
      .add(new BigInteger("10").pow(i))
      .multiply(values[i])
      .mod(q)
      .mod(q);
  }
  return h;
}

function valid_vote_proof(pk, v, a, b, r) {
  let a0, a1, b0, b1, c0, c1, r0, r1;
  let c;

  if (v === 0) {
    c1 = new BigInteger(random(0, q - 1).toString());
    r0 = new BigInteger(random(0, q - 1).toString());
    r1 = new BigInteger(random(0, q - 1).toString());

    a1 = g.modPow(r1, p).multiply(new BigInteger(a).modPow(new BigInteger(c1).multiply(p.subtract(2)), p)); //(pow(g, r1, p) * pow(a, c1 * (p - 2), p)) % p;
    b1 = pk.modPow(r1, p).multiply(
      b
        .pow(g, p.subtract(2), p)
        .mod(p)
        .modPow(c1.multiply(p.subtract(2), p))
    );
    a0 = g.modPow(r0, p);
    b0 = pk.modPow(r0, p);
    c = customHash([pk, a, b, a0, b0, a1, b1]);
    c0 = c1.subtract(c).abs();

    c0 = q.add(c1.subtract(c).mod(q)).mod(q);

    r0 = r0.add(c0.multiply(r).mod(q)).mod(q);

    return [a0, a1, b0, b1, c0, c1, r0, r1];
  } else if (v === 1) {
    c0 = new BigInteger(random(0, q - 1).toString());
    r0 = new BigInteger(random(0, q - 1).toString());
    r1 = new BigInteger(random(0, q - 1).toString());
    a0 = g
      .modPow(r0, p)
      .multiply(a.modPow(c0.multiply(p.subtract(2))), p)
      .mod(p);
    b0 = pk
      .modPow(r0, p)
      .multiply(b.modPow(c0.multiply(p.subtract(2))), p)
      .mod(p);
    a1 = g.modPow(r1, p);
    b1 = pk.modPow(r1, p);
    c = customHash([pk, a, b, a0, b0, a1, b1]);
    c1 = c0.subtract(c).abs();
    c1 = q.add(c0.subtract(c).mod(q)).mod(q);
    r1 = r1.add(c1.multiply(r).mod(q)).mod(q);
    return [a0, a1, b0, b1, c0, c1, r0, r1];
  } else {
    return [0, 0, 0, 0, 0, 0, 0, 0];
  }
}

async function encrypt(vote) {
  var r = await getRandomBigIntAsync(new BigInteger("3"), q_prev);
  var a = g.modPow(r, p);
  var b = g
    .modPow(new BigInteger(vote.toString()), p)
    .multiply(pk.modPow(r, p))
    .mod(p);
  var proof = valid_vote_proof(pk, vote, a, b, r);
  return [a, b, proof];
}

function decrypt(sk, a, b) {
  var ai = a.modPow(sk.multiply(p.subtract(new BigInteger("2"))), p);
  var gm = b.multiply(ai).mod(p);
  var m = new BigInteger("0");
  while (g.modPow(m, p).compareTo(gm) !== 0) {
    m = m.add(new BigInteger("1"));
  }
  return m;
}

function verify_vote(pk, a, b, proof) {
  a0 = proof[0];
  a1 = proof[1];
  b0 = proof[2];
  b1 = proof[3];
  c0 = proof[4];
  c1 = proof[5];
  r0 = proof[6];
  r1 = proof[7];

  s1 = g.modPow(r0, p).compareTo(a0.multiply(a.modPow(c0, p)).mod(p)) === 0;
  s2 = g.modPow(r1, p).compareTo(a1.multiply(a.modPow(c1, p)).mod(p)) === 0;
  s3 = pk.modPow(r0, p).compareTo(b0.multiply(b.modPow(c0, p)).mod(p)) === 0;
  power_base = b.multiply(g.modPow(p.subtract(new BigInteger("2")), p)).mod(p);
  s4 = pk.modPow(r1, p).compareTo(b1.multiply(power_base.modPow(c1, p)).mod(p)) === 0;

  return s1 && s2 && s3 && s4;
}

async function main() {
  encrypted = await encrypt(1);
  // console.log(encrypted[0].toString());
  // console.log(encrypted[1].toString());

  decrypted = decrypt(secret_key, encrypted[0], encrypted[1]);
  console.log(decrypted.toString());

  proof = verify_vote(pk, encrypted[0], encrypted[1], encrypted[2]);

  console.log(proof);
}

main();
