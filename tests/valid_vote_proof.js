import BigInteger from "jsbn";

function validVoteProof(pk, v, a, b, r) {
  let a0, a1, b0, b1, c0, c1, r0, r1;
  let c;

  if (v === 0) {
    c1 = random(0, q - 1);
    r0 = random(0, q - 1);
    r1 = random(0, q - 1);

    a1 = (pow(g, r1, p) * pow(a, c1 * (p - 2), p)) % p;
    b1 = (pow(pk, r1, p) * pow((b * pow(g, p - 2, p)) % p, c1 * (p - 2), p)) % p;

    a0 = pow(g, r0, p);
    b0 = pow(pk, r0, p);

    c = customHash([pk, a, b, a0, b0, a1, b1]);
    // TODO: There is a problem with the notation in the paper.
    // c0 = Math.abs(c1 - c);
    c0 = (q + ((c1 - c) % q)) % q;

    r0 = (r0 + ((c0 * r) % q)) % q;
    return [a0, a1, b0, b1, c0, c1, r0, r1];
  } else if (v === 1) {
    c0 = random(0, q - 1);
    r0 = random(0, q - 1);
    r1 = random(0, q - 1);

    a0 = (pow(g, r0, p) * pow(a, c0 * (p - 2), p)) % p;
    b0 = (pow(pk, r0, p) * pow(b, c0 * (p - 2), p)) % p;

    a1 = pow(g, r1, p);
    b1 = pow(pk, r1, p);

    c = customHash([pk, a, b, a0, b0, a1, b1]);
    // TODO: There is a problem with the notation in the paper.
    // c1 = Math.abs(c0 - c);
    c1 = (q + ((c0 - c) % q)) % q;

    r1 = (r1 + ((c1 * r) % q)) % q;
    return [a0, a1, b0, b1, c0, c1, r0, r1];
  } else {
    // an adversary will tweak the code below
    return [0, 0, 0, 0, 0, 0, 0, 0];
  }
}
