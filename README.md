# LiveLabs Auth

This is a simple library to authenticate using JWT tokens. This library should be used by a server 
that provides login / register / logout endpoints and partially by any other server that needs to
authenticate users, as long as both kinds of servers share the same secret. 

Impoirtant: Secret should never be shared with the client.

## How to implement authentication server

The authentication server is a simple server that should have `Storage` interface implemented.
The `Storage` interface is responsible for storing and retrieving user data. The server should
also have a secret that is used to sign JWT tokens. The secret should be shared with other servers
that need to authenticate users.

Having `Storage` interface implemented, the server should create an instance of `UsersRegistry`, 
that provides methods to register, login and logout users. Implementation of the http handlers
or any other logic is up to the developer.

## How to implement other servers, that need to authenticate users

Other servers should have a secret that is shared with the authentication server. The secret is
used to verify JWT tokens. The server should create an instance of `Authenticator` and use it
to authenticate users. Authenticator is the hhtp middleware wrapper around the http handler, that 
checks `Authorization` header and verifies JWT token. If the token is valid and user has any/all of 
the expected roles, the request is passed to the handler, otherwise the request is rejected with
`401 Unauthorized` status code. 

## Roles

Roles are strings that are used to check if the user has access to the resource. There is only one
predefined special role `admin`. The `admin` role is used to check if the user has universal access
to any resource. Any other role is up to the developer to define.

## License

This software is licensed under the MIT license. See [LICENSE](LICENSE) for details.

