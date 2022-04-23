import BigInteger from "jsbn";
import crypto from "crypto";

function random(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
// PUBLIC PARAMETERS
var p = new BigInteger("142950481577612897377251366207350601085193026787763232208511322259955075211826388565191137969675785957228922178875744018870301928203434246727650650452188476517559379655516949015006180412307375960073546778478575555767086902406147563214485604901264760329721957156402926704404814419844454185694597535438114709207");
var q = new BigInteger("71475240788806448688625683103675300542596513393881616104255661129977537605913194282595568984837892978614461089437872009435150964101717123363825325226094238258779689827758474507503090206153687980036773389239287777883543451203073781607242802450632380164860978578201463352202407209922227092847298767719057354057");
var q_prev = q.subtract(new BigInteger("1"));
var g = new BigInteger("5");

// ==========================================
// private parameters
var secret_key = new BigInteger("2380831451759006579882553120960984113277981577916531573623778541891671800956226624640322916414543030985934711395325938960305715079214976582052109890021687068");
function generate_pk(sk) {
  return g.modPow(sk, p);
}
// ==========================================

async function getRandomBigIntAsync(min, max) {
  const range = max.subtract(min).subtract(BigInteger.ONE);

  let bi;
  do {
    // Generate random bytes with the length of the range
    const buf = await crypto.randomBytesAsync(Math.ceil(range.bitLength() / 8));

    // Offset the result by the minimum value
    bi = new BigInteger(buf.toString("hex"), 16).add(min);
  } while (bi.compareTo(max) >= 0);

  // Return the result which satisfies the given range
  return bi;
}

function validate_vote_proof(pk, vote, a, b, r) {
  let a0, a1, b0, b1, c0, c1, r0, r1;
  let c;

  if(vote === "0") {
    c1 = await getRandomBigIntAsync(new BigInt('0'), q_prev);
    r0 = await getRandomBigIntAsync(new BigInt('0'), q_prev);
    r1 = await getRandomBigIntAsync(new BigInt('0'), q_prev);

    a1 = g.modPow(r1, p).multiply(a.modPow(c1.multiply(p.subtract(new BigInteger("2"))), p)).mod(p);
  }
}

var pk = generate_pk(secret_key);

function encrypt(vote) {
  // Avoid g=2 because of Bleichenbacher's attack
  var r = await getRandomBigIntAsync(new BigInt('3'), q_prev);
  var a = g.modPow(r, p);
  var b = g.modPow(new BigInteger(vote.toString())).multiply(pk.modPow(r, p)).mod(p);
}

function encrypt(pk, v) {
  let r = random(0, q - 1);
  let a = pow(g, r, p);
  let b = (pow(g, v, p) * pow(pk, r, p)) % p;
  let proof = validVoteProof(pk, v, a, b, r);
  return [a, b, proof];
}
