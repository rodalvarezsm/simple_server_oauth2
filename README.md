### Learning OAuth2 by implementing a simple server

#### Grant endpoint

/token

Grant type used is client credentials. ClientId and ClientSecret are sent in Authorization header (Basic Authentication). Scope is always "all".

#### List of public keys

/jwks

Uses Basic Authentication. Expects the same credentials as the Grant Endpoint, as it uses ClientId to identify which keys to list.

#### Future improvements

- Key management: right now the app generates a new key pair for each token request. It would be better to have a set 
of key pairs stored and pick from them.
- Use a store that is not in-memory
- Using cache
- Ability to revoke a token
- Refresh tokens