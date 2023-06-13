### Learning OAuth2 by implementing a simple server

#### Grant endpoint

/token

Grant type used is client credentials. ClientId and ClientSecret are sent in Authorization header (Basic Authentication). Scope is always "all".

#### Future improvements

- Use a store that is not in-memory
- Using cache
- Ability to revoke a token
- Refresh tokens