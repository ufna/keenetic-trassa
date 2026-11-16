import { argon2idAsync } from '@noble/hashes/argon2';
import { hmac } from '@noble/hashes/hmac';
import { sha3_512 } from '@noble/hashes/sha3';
const bytes = s => new TextEncoder().encode(s);
const decode = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const encode = b => btoa(String.fromCharCode(...b));
const mac = (key, msg) => hmac(sha3_512, key, bytes(msg));
const xor = (a,b) => a.map((v,i) => v ^ b[i]);
window.TrassaNDW4 = async function(api, ch, login, password) {
  let nonce = encode(crypto.getRandomValues(new Uint8Array(16)));
  let send = (id, response) => api('POST','/api/login',{id,login,response});
  let a = await send(ch.id, nonce);
  let {salt, nonce:n, iter, memcost} = a.data;
  if (!Number.isInteger(iter) || iter < 1 || iter > 20 ||
      !Number.isInteger(memcost) || memcost < 8 || memcost > 262144 ||
      decode(salt).length !== 16 || typeof n !== "string" || n.length < 1 || n.length > 256)
    throw new Error('Invalid NDW4 challenge');
  let k = await argon2idAsync(bytes(password),decode(salt),{t:iter,m:memcost,p:1,dkLen:64});
  let ck = mac(k,'NDW4 Interactive Client Key'), sk = sha3_512(ck), srv = mac(k,'NDW4 Interactive Server Key');
  let msg = `login1=${login},nonce1=${nonce};iter2=${iter},memcost2=${memcost},nonce2=${n},salt2=${salt};login3=${login},nonce3=${n}`;
  let r = await send(a.id,encode(xor(ck,mac(sk,msg))));
  let sig = decode(r.data.signature), expected = mac(srv,msg);
  if (sig.length !== expected.length || expected.reduce((acc,v,i)=>acc|(v^sig[i]),0))
    throw new Error('Keenetic did not verify the NDW4 password proof');
  await send(r.id,encode(xor(ck,mac(sk,msg+';signature4='+r.data.signature))));
};
