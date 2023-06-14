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

Requires the parameter "token" in the body.

Example request (change token for the one to inspect)

`curl -v -H "Authorization: Basic dXNlcnRlc3Q6cGFzc3Rlc3Q=" -X POST -d "token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjhjOTQxYTNkLTM2NmItNDRlMC05ZTQ4LTlkYzUyOGVjNWZhOSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2ODY3NzI0NDcsImlhdCI6MTY4Njc2ODgzNywianRpIjoiYzVhYzczMDEtNzUxMC00MzE3LWEyNTEtOTI4NWViNzY0OWRiIiwic3ViIjoidXNlcnRlc3QifQ.Er705r45eeu_o1QsGftHOnJ88DQTE0-cxuE_CIApe3fBAGRKVTNvUjVVavUHOcsPdaOWOXdWu5Fk_Fm08PuGov2H5PCx0w1tSAYse2G-08J6ITPagkRedJtctjMYhSuWbqsVUj9MUHEp_4QTY-4DUcEfghsuvCVRqA-TcCdnm7v-q1jt3af2e77Ljsz0-HKh3_HR_SqUwbeiluW3DNfcrqTBomDRggK9QRJyCEQGAyesF6th-_7TAzemEupfyUcgZQR6QTiJuubP7DsJ5ambSIAnNLnlicJ0Q-YGXOFqcqj7Uki99pb2YuV0Su5y4jvFkrBKsQnNsVaHq2sKph5L0g" localhost:8080/token_info`

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

Docker
```
docker build -t "simple_server_oauth2" .
docker run -p 8080:8080 simple_server_oauth2
```

#### Future improvements

- Credentials: add an endpoint to store credentials (right now only one pair is available and is hardcoded).
- Use Argon2 to hash credentials' password in the store.
- Key management: right now the app generates a new key pair for each token request. It would be better to have a set 
of key pairs stored and pick from them.
- Add a store for issued tokens.
- Use a store that is not in-memory.
- Using cache.
- Ability to revoke a token.
- Refresh tokens.