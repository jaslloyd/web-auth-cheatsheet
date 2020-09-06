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

# SAML

Security Assertion Markup Language 2.0 (SAML 2.0) is a version of the SAML standard for exchanging authentication and authorization identities between security domains.

SAML 2.0 is an XML-based protocol that uses security tokens containing assertions to pass information about a principal (usually an end user) between an Identity Provider(SAML authority), and a Service Provider(SAML consumer).

SAML enabled web-based cross domain SSO.

## Assertions

An assertion is a package of information that supplies zero or more statements made by a SAML authority. The SAML 2.0 specification defines three different kinds of assertion statements:

- Authentication Assertion: The assertion subject was authenticated by a particular means at a particular time.
- Attribute Assertion: The assertion subject is associated with the supplied attributes.
- Authorization Decision Assertion: A request to allow the assertion subject to access the specified resource has been granted or denied.

An important type of SAML assertion is the so-called "bearer" assertion used to facilitate Web Browser SSO. Here is an example of a short-lived bearer assertion issued by an identity provider (https://idp.example.org/SAML2) to a service provider (https://sp.example.com/SAML2).

```XML
<!-- In english:
The assertion ("b07b804c-7c29-ea16-7300-4f3d6f7928ac") was issued at time "2004-12-05T09:22:05Z" by identity provider (https://idp.example.org/SAML2) regarding subject (3f7b3dcf-1674-4ecd-92c8-1544f346baf8) exclusively for service provider (https://sp.example.com/SAML2). -->
<saml:Assertion
   xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
   xmlns:xs="http://www.w3.org/2001/XMLSchema"
   ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75"
   Version="2.0"
   IssueInstant="2004-12-05T09:22:05Z">
   <!-- IDP server that issues the request -->
   <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
   <!-- which contains an integrity-preserving digital signature  -->
   <ds:Signature
     xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:Signature>
   <!-- This is the user or principal the assertion is for -->
   <saml:Subject>
     <saml:NameID
       Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
       3f7b3dcf-1674-4ecd-92c8-1544f346baf8
     </saml:NameID>
     <saml:SubjectConfirmation
       Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
       <saml:SubjectConfirmationData
         InResponseTo="aaf23196-1773-2113-474a-fe114412ab72"
         Recipient="https://sp.example.com/SAML2/SSO/POST"
         NotOnOrAfter="2004-12-05T09:27:05Z"/>
     </saml:SubjectConfirmation>
   </saml:Subject>
   <!-- which gives the conditions under which the assertion is to be considered valid  -->
   <saml:Conditions
     NotBefore="2004-12-05T09:17:05Z"
     NotOnOrAfter="2004-12-05T09:27:05Z">
     <saml:AudienceRestriction>
        <!-- Service Provider this assertion is for -->
       <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
     </saml:AudienceRestriction>
   </saml:Conditions>
   <!-- This is an Authentication Assertion -->
   <!-- <saml:Subject> element was authenticated at time "2004-12-05T09:22:00Z" by means of a password sent over a protected channel. -->
   <saml:AuthnStatement
     AuthnInstant="2004-12-05T09:22:00Z"
     SessionIndex="b07b804c-7c29-ea16-7300-4f3d6f7928ac">
     <saml:AuthnContext>
       <saml:AuthnContextClassRef>
         urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
       </saml:AuthnContextClassRef>
     </saml:AuthnContext>
   </saml:AuthnStatement>
   <!-- This is an Attribute Assertion -->
   <!-- The principal identified in the <saml:Subject> element is a staff member at this institution. -->
   <saml:AttributeStatement>
     <saml:Attribute
       xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500"
       x500:Encoding="LDAP"
       NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
       Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
       FriendlyName="eduPersonAffiliation">
       <saml:AttributeValue
         xsi:type="xs:string">member</saml:AttributeValue>
       <saml:AttributeValue
         xsi:type="xs:string">staff</saml:AttributeValue>
     </saml:Attribute>
   </saml:AttributeStatement>
 </saml:Assertion>

```

In SAML 2.0, the flow begins at the service provider who issues an explicit authentication request to the identity provider. When a principal (or an entity acting on the principal's behalf) wishes to obtain an assertion containing an authentication statement, a <samlp:AuthnRequest> element is transmitted to the identity provider:

```xml
 <samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="aaf23196-1773-2113-474a-fe114412ab72"
    Version="2.0"
    IssueInstant="2004-12-05T09:21:59Z"
    AssertionConsumerServiceIndex="0"
    AttributeConsumingServiceIndex="0">
    <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
    <samlp:NameIDPolicy
      AllowCreate="true"
      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
  </samlp:AuthnRequest>
```

This SAML request is sent to the LDP via the browser, this AuthnRequest identifies the service provider (https://sp.example.com/SAML2) to the ldp.

## SAML 2.0 Bindings

For Web Browser SSO, the HTTP Redirect Binding and the HTTP POST Binding are commonly used. For example, the service provider may use HTTP Redirect to send a request while the identity provider uses HTTP POST to transmit the response

### HTTP Redirect Binding

The HTTP Redirect binding is suitable for short messages, such as the <samlp:AuthnRequest> message. Longer messages are transmitted via other bindings such as HTTP Post Binding. Example of the `<samlp:AuthnRequest` request above sent to the IDP via query parameters is:

Before it's sent, the message(`<samlp:AuthnRequest)`) is deflated (without header and checksum), base64-encoded, and URL-encoded, in that order

```xml
 https://idp.example.org/SAML2/SSO/Redirect?SAMLRequest=fZFfa8IwFMXfBb9DyXvaJtZ1BqsURRC2
 Mabbw95ivc5Am3TJrXPffmmLY3%2FA15Pzuyf33On8XJXBCaxTRmeEhTEJQBdmr%2FRbRp63K3pL5rPhYOpkVdY
 ib%2FCon%2BC9AYfDQRB4WDvRvWWksVoY6ZQTWlbgBBZik9%2FfCR7GorYGTWFK8pu6DknnwKL%2FWEetlxmR8s
 BHbHJDWZqOKGdsRJM0kfQAjCUJ43KX8s78ctnIz%2Blp5xpYa4dSo1fjOKGM03i8jSeCMzGevHa2%2FBK5MNo1F
 dgN2JMqPLmHc0b6WTmiVbsGoTf5qv66Zq2t60x0wXZ2RKydiCJXh3CWVV1CWJgqanfl0%2Bin8xutxYOvZL18NK
 UqPlvZR5el%2BVhYkAgZQdsA6fWVsZXE63W2itrTQ2cVaKV2CjSSqL1v9P%2FAXv4C
```

Issuer and NameIDPolicy should be agreed upon by the Service provider and IDP.

### HTTP Post Binding

Both service provider and Identity provider use an HTTP POST binding.

SSO Profile
The service provider sends a SAML Request to the IdP SSO Service using the HTTP-Redirect Binding. The identity provider returns the SAML Response to the SP Assertion Consumer Service using the HTTP-POST Binding.

1. The principal (the user) request requests a target resource at the service provider, the SP checks performs a security check on behalf of the target resource. If a valid security context at the service provider already exists, skip steps 2–7.

2. Redirect to IdP SSO Service - The service provider generates an appropriate SAMLRequest (and RelayState, if any), then redirects the browser to the IdP SSO Service using a standard HTTP 302 redirect. e.g

```
302 Redirect
Location: https://idp.example.org/SAML2/SSO/Redirect?SAMLRequest=request&RelayState=token
```

The RelayState token is an opaque reference to state information maintained at the service provider. The value of the SAMLRequest parameter is a deflated, base64-encoded and URL-encoded value of an <samlp:AuthnRequest> see above^^

3. Request the SSO Service at the IdP e.g https://idp.example.org/SAML2/SSO/Redirect?SAMLRequest=request&RelayState=token

4. IDP Services up a XHTML Form to ask user to validate their credentials and Respond the submission. It generates a SAML response:

```xml
  <samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="identifier_2"
    InResponseTo="identifier_1"
    Version="2.0"
    IssueInstant="2004-12-05T09:22:05Z"
    Destination="https://sp.example.com/SAML2/SSO/POST">
    <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
    <samlp:Status>
      <samlp:StatusCode
        Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion
      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
      ID="identifier_3"
      Version="2.0"
      IssueInstant="2004-12-05T09:22:05Z">
      <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
      <!-- a POSTed assertion MUST be signed -->
      <ds:Signature
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#">...</ds:Signature>
      <saml:Subject>
        <saml:NameID
          Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">
          3f7b3dcf-1674-4ecd-92c8-1544f346baf8
        </saml:NameID>
        <saml:SubjectConfirmation
          Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
          <saml:SubjectConfirmationData
            InResponseTo="identifier_1"
            Recipient="https://sp.example.com/SAML2/SSO/POST"
            NotOnOrAfter="2004-12-05T09:27:05Z"/>
        </saml:SubjectConfirmation>
      </saml:Subject>
      <saml:Conditions
        NotBefore="2004-12-05T09:17:05Z"
        NotOnOrAfter="2004-12-05T09:27:05Z">
        <saml:AudienceRestriction>
          <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
        </saml:AudienceRestriction>
      </saml:Conditions>
      <saml:AuthnStatement
        AuthnInstant="2004-12-05T09:22:00Z"
        SessionIndex="identifier_3">
        <saml:AuthnContext>
          <saml:AuthnContextClassRef>
            urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
         </saml:AuthnContextClassRef>
        </saml:AuthnContext>
      </saml:AuthnStatement>
    </saml:Assertion>
  </samlp:Response>
```

5. Request the Assertion Consumer Service at the SP

The user agent (browser) issues a POST request to the Assertion Consumer Service at the service provider:

```
POST /SAML2/SSO/POST HTTP/1.1
Host: sp.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: nnn

SAMLResponse=response&RelayState=token
```

SAMLReponse - is deflated (without header and checksum), base64-encoded, and URL-encoded version of the `<samlp:Response`
RelayState - is the state we passed earlier.

6. Redirect to the target resource - The assertion consumer service processes the response, creates a security context at the service provider and redirects the user agent to the target resource.

7. Request the target resource at the SP again - https://sp.example.com/myresource

8. Respond with requested resource

Since a security context exists, the service provider returns the resource to the user agent.

Questions

- "The assertion consumer service processes the response, creates a security context at the service provider" - Is this a session ID? a jwt or something else?


## Resources

OAuth + JWTs

[Auth0 Docs](https://auth0.com/docs)

[OAuth Docs](https://www.oauth.com/)

[Id Tokens & Access Tokens](https://auth0.com/docs/tokens)

[LogRocket JWT Auth](https://blog.logrocket.com/jwt-authentication-best-practices/)

[Token Storage](https://auth0.com/docs/tokens/concepts/token-storage)

[Simple and Secure API Auth for SPAS](https://medium.com/@sadnub/simple-and-secure-api-authentication-for-spas-e46bcea592ad)

[The Ultimate Guide to handling JWTs on frontend clients](https://hasura.io/blog/best-practices-of-using-jwt-with-graphql/)
