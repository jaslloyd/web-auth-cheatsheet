# Web Authentication and Authorization Cheat sheet
Cheatsheet for Web Authentication 

I do not want to ever have to find or figure out this information ever again, I have spent the last months messing with web authitection and authorization on a work project and I want this repo to help future Jason or anybody else

## Table of Contents
1. [Authentication vs Authorization](#authentication-vs-authorization)
2. [Basic Authentication](#basic-authentication)
3. [Sessions](#sessions)
4. [OAuth](#oauth)

## Authentication vs Authorization
- Authentication is the process of verifying who a user is.
- Authorization is the process of verifying what they have access to.

## Basic Authentication

## Sessions

Session - Users session on the website, usually session id stored server side and cleared after certain amount of time.

Sessions are usually stored / validated on the server or if there is more than one server they are stored in something like Memcache or Redis i.e it a Stateful form of Authorization.

Session ID are usually sent from the client in a cookie or header, the server looks up that session id and checks if the user has permission to do what they are requesting.

## OAuth

### Grants

OAuth has various different flows/grants for different situations see [here](https://auth0.com/docs/api-auth/which-oauth-flow-to-use) for different use cases from Implicit being least secure to Authorization Code Flow be most secure.

#### Authorization Code Flow **CONFIRM**

- Recommended if your web app sits on a server or you have a BE server that goes along with your web app
- All communication is done with BE server and not through client browser \*There is a variation where first step is done through browser

The OAuth Authorization code redirection flow is:

1. User goes to /login page or is redirected there, that page either has a bunch of sign in options (e.g Google, Facebook etc).
2. User clicks options to sign in and application will be redirected to that Identity providers Sign in page.
3. Once the user signs in and gives permissions for the application the Identity provider redirects the user back to the application (i.e as specified in redirect_uri), along with that redirect there will be an Authorization code query parameter e.g: http://myawesomeapplication.com/auth_redirect?code=XYZ... This authorization code is a one time use code that our application can exchange for an access/id_token.
4. Our application extracts that code, sends another request with that token + our application client id & secret (usually Base64 encoded) to the identity provider (usually xyz.com/oauth/token)
5. The Identity provider validates the Authorization + Client ID + Client secret, if valid it returns and id token, access and refresh token to the application.
6. Our application can then use the access token to get more use information / get the information it requested access to.

#### Implicit

#### .....


## Resources

OAuth + JWTs

[Auth0 Docs](https://auth0.com/docs)

[Id Tokens & Access Tokens](https://auth0.com/docs/tokens)

[LogRocket JWT Auth](https://blog.logrocket.com/jwt-authentication-best-practices/)

[Token Storage](https://auth0.com/docs/tokens/concepts/token-storage)

[Simple and Secure API Auth for SPAS](https://medium.com/@sadnub/simple-and-secure-api-authentication-for-spas-e46bcea592ad)

[The Ultimate Guide to handling JWTs on frontend clients](https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/)
