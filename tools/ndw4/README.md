Regenerate the embedded browser asset with `npm install` and `npm run build`
from this directory. The pinned Noble Hashes dependency is MIT licensed;
its license accompanies the checked-in bundle. Node and npm are only needed
to regenerate the asset, never to build Trassa or run it on the router.

The browser performs Argon2id and the NDW4 proofs locally. The Go web server
relays the three steps to the same firmware /auth session, without receiving
the password. No browser resource is fetched from a CDN.
