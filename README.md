# LiveLabs Auth

This is a simple library to authenticate using JWT tokens. This library should be used by a server 
that provides login / register / logout endpoints and partially by any other server that needs to
authenticate users, as long as both kinds of servers share the same secret. 

Impoirtant: Secret should never be shared with the client.

## How to implement authentication server

The authentication server should have `Storage` interface implemented.
The `Storage` interface is responsible for storing and retrieving user data. The server should
also have a secret that is used to sign JWT tokens. The secret should be shared with other servers
that need to authenticate users.

_TODO_: in the next version, in addition to the secret, the server should also be able to use a private/public 
key pair to sign/verify JWT tokens.

Having `Storage` interface implemented, the server should create an instance of `Registry`, 
that provides methods to register, login and logout users. Implementation of the http handlers
is available in the `auth.server` package, but not limited to it, you can implement your own
handlers if you want to.

## How to implement other servers, that need to authenticate users

Other servers should have a `secret` that is shared with the authentication server. The secret is
used to verify JWT tokens. The server should create an instance of `Middleware` wraooer and use it
to check access to the wrapped endpoints. `Middleware` wraps around the http handler, and 
checks `Authorization` header and verifies JWT token. If the token is valid and user has any/all of 
the expected roles, the request is passed to the handler, otherwise the request is rejected with
`401 Unauthorized` status code. 

## Roles

Roles are strings that are used to check if the user has access to the resource. There is only one
predefined special role `admin`. The `admin` role is used to check if the user has universal access
to any resource. Any other role is up to the developer to define.

## License

This software is licensed under the MIT license. See [LICENSE](LICENSE) for details.

