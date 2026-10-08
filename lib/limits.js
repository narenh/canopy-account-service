// Too many tries at something, per key, per window. In memory: a restart
// forgives everyone, which is fine at this scale. Carried over from
// tickets' movie-password limits.
function attemptLimiter(max, windowMs) {
  const hits = new Map();
  return {
    blocked(key) {
      const h = hits.get(key);
      return !!h && Date.now() < h.reset && h.n >= max;
    },
    hit(key) {
      const now = Date.now();
      let h = hits.get(key);
      if (!h || now >= h.reset) { h = { n: 0, reset: now + windowMs }; hits.set(key, h); }
      h.n++;
      if (hits.size > 10000) hits.forEach((v, k) => { if (now >= v.reset) hits.delete(k); });
    }
  };
}

// The visitor's address. Cloudflare puts the real one in CF-Connecting-IP
// and overwrites anything the visitor sent; X-Forwarded-For (what req.ip
// reads, with trust proxy on) keeps whatever the visitor put first, so
// limiting on req.ip alone could be dodged by sending a fake one.
function clientIp(req) {
  return req.get('cf-connecting-ip') || req.ip;
}

// A family of limits checked together: per `who` (a person, an email, a
// browser), per address, and one ceiling across everyone -- the backstop
// when the first two are dodged with fresh emails and addresses. It trips
// for everyone, which is the point. `perWho` can be left out where there's
// no who worth counting (a quick sign-up is a new person every time).
function guessLimits({ perWho, perIp, overall }) {
  const who = perWho ? attemptLimiter(perWho[0], perWho[1]) : null;
  const ip = attemptLimiter(perIp[0], perIp[1]);
  const all = attemptLimiter(overall[0], overall[1]);
  return {
    blocked(req, key) {
      return (!!who && who.blocked(key)) || ip.blocked(clientIp(req)) || all.blocked('all');
    },
    hit(req, key) {
      if (who) who.hit(key);
      ip.hit(clientIp(req));
      all.hit('all');
    }
  };
}

module.exports = { attemptLimiter, guessLimits, clientIp };
