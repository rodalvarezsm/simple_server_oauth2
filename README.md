### Learning OAuth2 by implementing a simple server

#### Grant endpoint

`POST /token`

Grant type used is client credentials. ClientId and ClientSecret are sent in Authorization header (Basic Authentication). Scope is always "all".

Example request

`curl -v -H "Authorization: Basic dXNlcnRlc3Q6cGFzc3Rlc3Q=" -X POST localhost:8080/token`

#### List of public keys

`POST /jwks`

Uses Basic Authentication. Expects the same credentials as the Grant Endpoint, as it uses ClientId to identify which keys to list.

Example request

`curl -v -H "Authorization: Basic dXNlcnRlc3Q6cGFzc3Rlc3Q=" -X POST localhost:8080/jwks`

#### Introspection endpoint

`POST /token_info`

Requires the parameter "token".

Uses Basic Authentication. Expects the same credentials as the Grant Endpoint, as it uses ClientId to identify which keys to list.

Responses

In case of success
```json
{
  "active": true,
  "client_id": string,
  "expiry": int64
}
```

In case of non-valid token, expired or issued for another client

```json
{
  "active": false
}
```

#### How to run

Windows
```
go build cmd/main.go
.\main.exe
```

#### Future improvements

- Credentials: add an endpoint to store credentials (right now only one pair is available and is hardcoded).
- Key management: right now the app generates a new key pair for each token request. It would be better to have a set 
of key pairs stored and pick from them.
- Use a store that is not in-memory.
- Using cache.
- Ability to revoke a token.
- Refresh tokens.