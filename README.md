# Web Authentication and Authorization Cheat sheet

I do not want to ever have to find or figure out this information ever again, I have spent the last months messing with web authitection and authorization on a work project and I want this repo to help future Jason or anybody else

## Table of Contents
1. [Authentication vs Authorization](#authentication-vs-authorization)
2. [Sessions](#sessions)
3. [JWT](#jwt)
4. [Basic Authentication](#basic-authentication)
5. [OAuth](#oauth)
6. [SAML](#saml)
7. [Resources](#resources)

## Authentication vs Authorization
- Authentication is the process of verifying who a user is.
- Authorization is the process of verifying what they have access to.

## Sessions

Session - Users session on the website, usually session id stored server side and cleared after certain amount of time.

Sessions are usually stored / validated on the server or if there is more than one server they are stored in something like Memcache or Redis i.e it a Stateful form of Authorization.

Session ID are usually sent from the client in a cookie or header, the server looks up that session id and checks if the user has permission to do what they are requesting.

## JWT

- JWT or JSON web token is a stateless form of Authorization (JWT cannot be used to login but it can be used to verify access i.e it is for Authorization).
- It is stateless because the server(s) don't need to store anything a head of time unlike sessions. It is validated at time of use.
- JWT are sent with every request the client makes to a server (or a server makes to a server), there are a bunch of places you could possibly store the token which can be found below TODO
- JWT can be easily decypted which makes them visbile by the user, if the user changes the payload it will invalid the signature.

### JWT Example

JWT has the form `xxxxx.yyyyy.zzzzz`, example below:

**eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9**.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.*SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c*

JWT has three parts see above

- Header = Contains the type of the token and the signing Algorithm.
- Payload = Payload contains Claims that are statements about an entity (typically, the user) and additional data. Usually will contain an expiry date of JWT (exp), user details such as username and depending on the application may have more custom properties such as roles / groups
- Signature = The signature is used to verify the message wasn't changed along the way


## Basic Authentication
// TODO...


## OAuth

### Grants

OAuth has various different flows/grants for different situations see [here](https://auth0.com/docs/api-auth/which-oauth-flow-to-use) for different use cases Authorization Code Flow is the most secure. Authorization code flow is briefly described below, if you interested in seeing others check out this [post](https://alexbilbie.com/guide-to-oauth-2-grants/)

#### Authorization Code Flow

- Recommended if your web app sits on a server or you have a BE server that goes along with your web app
- All communication is done with BE server and not through client browser

The OAuth Authorization code redirection flow is:

1. User goes to /login page or is redirected there, that page either has a bunch of sign in options (e.g Google, Facebook etc).
2. User clicks options to sign in and application will be redirected to that Identity providers Sign in page.
3. Once the user signs in and gives permissions for the application the Identity provider redirects the user back to the application (i.e as specified in redirect_uri), along with that redirect there will be an Authorization code query parameter e.g: http://myawesomeapplication.com/auth_redirect?code=XYZ... This authorization code is a one time use code that our application can exchange for an access/id_token.
4. Our application extracts that code, sends another request with that token + our application client id & secret (usually Base64 encoded) to the identity provider (usually xyz.com/oauth/token)
5. The Identity provider validates the Authorization + Client ID + Client secret, if valid it returns and id token, access and refresh token to the application.
6. Our application can then use the access token to get more use information / get the information it requested access to.


## SAML

SAML or Security Assertion Markup Language is a version of the SAML standard for exchanging authentication and authorization identities between security domains.

- SAML is an XML-based protocol that allows cross domain SSO
- Uses security tokens containing assertions to pass information about a principal / end user between an Identity Provider(SAML authority) and a Service Provider(SAML consumer).
- When a user signs in the Identity Provider issues an assertion. There are three kinds of assertion statements:
  - Authentication Assertion: Specifies who created the assertion, what time it was created at and details about the assertion subject (the user)
  - Attribute Assertion: Specifices the attributes / properties associated with the subject(the user) e.g: Role, Group, isAdmin etc
  - Authorization Decision Assertion: Specifices if the Subject access request for the specific resource has been granted or denied.

### SAML Flows

// TODO:

## Resources

OAuth + JWTs

[Auth0 Docs](https://auth0.com/docs)

[OAuth Docs](https://www.oauth.com/)

[Id Tokens & Access Tokens](https://auth0.com/docs/tokens)

[LogRocket JWT Auth](https://blog.logrocket.com/jwt-authentication-best-practices/)

[Token Storage](https://auth0.com/docs/tokens/concepts/token-storage)

[Simple and Secure API Auth for SPAS](https://medium.com/@sadnub/simple-and-secure-api-authentication-for-spas-e46bcea592ad)

[The Ultimate Guide to handling JWTs on frontend clients](https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/)
