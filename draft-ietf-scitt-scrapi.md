---
v: 3

title: SCITT Reference APIs
abbrev: SCRAPI
docname: draft-ietf-scitt-scrapi-latest
stand_alone: true
area: Security
wg: SCITT
kw: Internet-Draft
cat: std
consensus: yes
submissiontype: IETF
ipr: trust200902
pi:
  toc: yes
  sortrefs: yes
  symrefs: yes

kramdown_options:
  auto_id_prefix: sec-

venue:
  group: SCITT
  mail: scitt@ietf.org
  github: ietf-wg-scitt/draft-ietf-scitt-scrapi

author:
- name: Henk Birkholz
  org: Fraunhofer SIT
  abbrev: Fraunhofer SIT
  email: henk.birkholz@sit.fraunhofer.de
  street: Rheinstrasse 75
  code: '64295'
  city: Darmstadt
  country: Germany
- ins: O. Steele
  name: Orie Steele
  organization: Transmute
  email: orie@transmute.industries
- ins: J. Geater
  name: Jon Geater
  organization: DataTrails Inc.
  email: jon.geater@datatrails.ai
  country: UK
  country: United States

normative:
  RFC9052:
  RFC7807:
  RFC7231:
  RFC3553:
  RFC5785:
  RFC8792:

  IANA.params:
  I-D.draft-ietf-scitt-architecture: SCITT-ARCH

informative:
  I-D.draft-demarco-oauth-nonce-endpoint: Nonce-Endpoint
  I-D.draft-ietf-oauth-sd-jwt-vc: SD-JWT-VC
  RFC2046:
  RFC6838:

--- abstract

This document describes a REST API that supports the normative requirements of the SCITT Architecture {{-SCITT-ARCH}}.
Optional key discovery and query interfaces are provided to support interoperability issues with Decentralized Identifiers, X509 Certificates and Artifact Repositories.

--- middle

# Introduction

The SCITT Architecture {{-SCITT-ARCH}} defines the core operations necessary to support supply chain transparency using COSE (CBOR Object Signing and Encryption).

- Issuance of Signed Statements
- Verification of Signed Statements

- Registration of Signed Statements

- Issuance of Receipts
- Verification of Receipts

- Production of Transparent Statements
- Verification of Transparent Statements

In addition to defining concrete HTTP endpoints for these operations, this specification defines support for the following endpoints which support these operations:

- Resolving Verification Keys for Issuers
- Retrieving Receipts Asynchronously
- Retrieving Signed Statements from an Artifact Repository
- Retrieving Statements from an Artifact Repository

## Terminology

{::boilerplate bcp14-tagged}

This specification uses the terms "Signed Statement", "Receipt", "Transparent Statement", "Artifact Repositories", "Transparency Service", "Append-Only Log" and "Registration Policy" as defined in {{-SCITT-ARCH}}.

This specification uses "payload" as defined in {{RFC9052}}.

# Endpoints

Authentication is out of scope for this document.
If Authentication is not implemented, rate limiting or other denial of service mitigations MUST be applied to enable anonymous access.

NOTE: '\' line wrapping per {{RFC8792}} in HTTP examples.

All messages are sent as HTTP GET or POST requests.

If the Transparency Service cannot process a client's request, it MUST return an HTTP 4xx or 5xx status code, and the body SHOULD be a JSON problem details object ({{RFC7807}}) containing:

- type: A URI reference identifying the problem.
To facilitate automated response to errors, this document defines a set of standard tokens for use in the type field within the URN namespace of: "urn:ietf:params:scitt:error:".

- detail: A human-readable string describing the error that prevented the Transparency Service from processing the request, ideally with sufficient detail to enable the error to be rectified.

Error responses SHOULD be sent with the `Content-Type: application/problem+json` HTTP header.

As an example, submitting a Signed Statement with an unsupported signature algorithm would return a `400 Bad Request` status code and the following body:

~~~json
{
  "type": "urn:ietf:params:scitt:error:badSignatureAlgorithm",
  "detail": "Signing algorithm not support"
}
~~~

Most error types are specific to the type of request and are defined in the respective subsections below.
The one exception is the "malformed" error type, which indicates that the Transparency Service could not parse the client's request because it did not comply with this document:

- Error code: `malformed` (The request could not be parsed).

Clients SHOULD treat 500 and 503 HTTP status code responses as transient failures and MAY retry the same request without modification at a later date.
Note that in the case of a 503 response, the Transparency Service MAY include a `Retry-After` header field per {{RFC7231}} in order to request a minimum time for the client to wait before retrying the request.
In the absence of this header field, this document does not specify a minimum.

## Mandatory

The following HTTP endpoints are mandatory to implement to enable conformance to this specification.

### Transparency Configuration

Authentication SHOULD NOT be implemented for this endpoint.
This endpoint is used to discovery the capabilities of a transparency service implementing this specification.

Request:

~~~ http-message

GET /.well-known/transparency-configuration HTTP/1.1
Host: transparency.example
Accept: application/json
~~~

Response:

~~~ http-message
HTTP/1.1 200 Ok
Content-Type: application/json

{
  "issuer": "https://transparency.example",
  "registration_endpoint": "https://transparency.example/entries",
  "nonce_endpoint": "https://transparency.example/nonce",

  "registration_policy": \
"https://transparency.example\
/statements/urn:ietf:params:scitt:statement\
:sha-256:base64url:5i6UeRzg1...qnGmr1o",

  "supported_signature_algorithms": ["ES256"],
  "jwks": {
    "keys": [
      {
        "kid": "urn:ietf:params:oauth:\
jwk-thumbprint:sha-256:DgyowWs04gfVRim5i1WlQ-HFFFKI6Ltqulj1rXPagRo",
        "alg": "ES256",
        "use": "sig",
        "kty": "EC",
        "crv": "P-256",
        "x": "p-kZ4uOASt9IjQRTrWikGnlbGb-z3LU1ltwRjZaOS9w",
        "y": "ymXE1yltJPXgjQSRe9NweN3TLlSUALYZTzy83NVfdg0"
      },
      {
        "kid": "urn:ietf:params:oauth:\
jwk-thumbprint:sha-256:4Fzx5HO1W0ob9CZNc3RJx28Ixpgy9JAFM8jyXKW0ClE",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "use": "enc",
        "kty": "EC",
        "crv": "P-256",
        "x": "Vreuil95vzR6ixutgBBf2ota-rj97MvKfuJWB4qqp5w",
        "y": "NkUTeaoNlLRRsVRxHGDA-RsA0ex2tSpcd3G-4SmKXbs"
      }
    ]
  }
}
~~~

Additional fields may be present.
Fields that are not understood MUST be ignored.

### Signed Statement Registration

Authentication MUST be implemented for this endpoint.

The following is a non-normative example of a HTTP request to register a Signed Statement:

Request:

~~~http
POST /entries HTTP/1.1
Host: transparency.example
Accept: application/json
Content-Type: application/cose
Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

The Registration Policy for the Transparency Service MUST be applied to the payload bytes, before any additional processing is performed.

If the `payload` is detached, the Transparency Service depends on the authentication context of the client in the Registration Policy.
If the `payload` is attached, the Transparency Service depends on both the authentication context of the client, and the verification of the Signed Statement in the Registration Policy.
The details of Registration Policy are out of scope for this document.

If registration succeeds the following identifier MAY be used to refer to the Signed Statement that was accepted:

`urn:ietf:params:scitt:signed-statement:sha-256:base64url:5i6UeRzg1...qnGmr1o`

If the `payload` was attached, or otherwise communicated to the Transparency Service, the following identifier MAY be used to refer to the `payload` of the Signed Statement:

`urn:ietf:params:scitt:statement:sha-256:base64url:5i6UeRzg1...qnGmr1o`

Response:

One of the following:

#### Status 201 - Registration is successful

~~~ http-message
HTTP/1.1 201 Ok

Location: https://transparency.example/receipts\
/urn:ietf:params:scitt:signed-statement\
:sha-256:base64url:5i6UeRzg1...qnGmr1o

Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

The response contains the Receipt for the Signed Statement.
Fresh receipts may be requested through the resource identified in the Location header.

#### Status 202 - Registration is running

~~~ http-message
HTTP/1.1 202 Ok

Location: https://transparency.example/receipts\
/urn:ietf:params:scitt:signed-statement\
:sha-256:base64url:5i6UeRzg1...qnGmr1o

Content-Type: application/json
Retry-After: <seconds>

{

  "receipt": "urn:ietf:params:scitt:receipt\
:sha-256:base64url:5i6UeRzg1...qnGmr1o",

}

~~~

The response contains a reference to the receipt which will eventually be available for the Signed Statement.

If 202 is returned, then clients should wait until Registration succeeded or failed by polling the receipt endpoint using the receipt identifier returned in the response.

#### Status 400 - Invalid Client Request

One of the following errors:

~~~
{
  "type": "urn:ietf:params:scitt:error\
:signed-statement:algorithm-not-supported",
  "detail": \
"Signed Statement contained an algorithm that is not supported."
}
~~~

~~~
{
  "type": "urn:ietf:params:scitt:error\
:signed-statement:payload-missing",
  "detail": \
"Signed Statement payload must be attached (must be present)"
}
~~~

~~~
{
  "type": "urn:ietf:params:scitt:error\
:signed-statement:payload-forbidden",
  "detail": \
"Signed Statement payload must be detached (must not be present)"
}
~~~

~~~
{
  "type": "urn:ietf:params:scitt:error\
:signed-statement:rejected-by-registration-policy",
  "detail": \
"Signed Statement was not accepted by the current Registration Policy"
}
~~~

~~~
{
  "type": "urn:ietf:params:scitt:error\
:signed-statement:confirmation-missing",
  "detail": \
"Signed Statement did not contain proof of possession"
}
~~~

TODO: other error codes

## Optional Endpoints

The following HTTP endpoints are optional to implement.

### Issue Statement

Authentication MUST be implemented for this endpoint.

This endpoint enables a Transparency Service to be an issuer of Signed Statements on behalf of authenticated clients.
This supports cases where a client lacks the ability to perform complex cryptographic operations, but can be authenticated and report statements and measurements.

Request:

~~~http
POST /signed-statements/issue HTTP/1.1
Host: transparency.example
Accept: application/json
Content-Type: application/vc+ld+json
Payload

{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://www.w3.org/ns/credentials/examples/v2"
  ],
  "id": "https://transparency.example/credentials/1872",
  "type": ["VerifiableCredential", "SensorCredential"],
  "issuer": "https://transparency.example/device/1234",
  "validFrom": "2010-01-01T19:23:24Z",
  "credentialSubject": {
    "type": "Feature",
    "geometry": {
      "type": "Point",
      "coordinates": [125.6, 10.1]
    },
    "properties": {
      "name": "Dinagat Islands"
    }
  }
}
~~~

Response:

~~~ http-message
HTTP/1.1 200 Ok
Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

### Resolve Statement

Authentication SHOULD be implemented for this endpoint.

This endpoint enables Transparency Service APIs to act like Artifact Repositories, and serve `payload` values directly, instead of indirectly through Receipts.

Request:

~~~ http-message
GET /statements/urn...qnGmr1o HTTP/1.1
Host: transparency.example
Accept: application/pdf
~~~

Response:

~~~ http-message
HTTP/1.1 200 Ok
Content-Type: application/pdf
Payload (pdf bytes)
~~~

### Resolve Signed Statement

Authentication SHOULD be implemented for this endpoint.

This endpoint enables Transparency Service APIs to act like Artifact Repositories, and serve Signed Statements directly, instead of indirectly through Receipts.

Request:

~~~ http-message
GET /signed-statements/urn...qnGmr1o HTTP/1.1
Host: transparency.example
Accept: application/cose
~~~

Response:

~~~ http-message
HTTP/1.1 200 Ok
Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

### Resolve Receipt

Authentication SHOULD be implemented for this endpoint.

Request:

~~~ http-message
GET /receipts/urn...qnGmr1o HTTP/1.1
Host: transparency.example
Accept: application/cose
~~~

Response:

If the Signed Statement requested is already included in the Append-Only Log:

~~~ http-message
HTTP/1.1 200 Ok
Location: https://transparency.example/receipts/urn...qnGmr1o
Content-Type: application/cose

Payload (in CBOR diagnostic notation)

18([                            / COSE Sign1         /
  h'a1013822',                  / Protected Header   /
  {},                           / Unprotected Header /
  null,                         / Detached Payload   /
  h'269cd68f4211dffc...0dcb29c' / Signature          /
])
~~~

If the Signed Statement requested is not yet included in the Append-Only Log:

~~~ http-message
HTTP/1.1 202 Ok
Location: https://transparency.example/receipts/urn...qnGmr1o
Content-Type: application/json
Retry-After: <seconds>

{
  "receipt": "urn:ietf:params:scitt:receipt\
    :sha-256:base64url:5i6UeRzg1...qnGmr1o",
}
~~~

Additional eventually consistent operation details MAY be present.
Support for eventually consistent Receipts is implementation specific, and out of scope for this specification.

### Resolve Issuer

This endpoint is inspired by {{-SD-JWT-VC}}.
Authentication SHOULD NOT be implemented for this endpoint.
This endpoint is used to discover verification keys, which is the reason that authentication is not required.

The following is a non-normative example of a HTTP request for the Issuer Metadata configuration when `iss` is set to `https://transparency.example/tenant/1234`:

Request:

~~~ http-message

GET /.well-known/issuer/tenant/1234 HTTP/1.1
Host: transparency.example
Accept: application/json
~~~

Response:

~~~ http-message
HTTP/1.1 200 Ok
Content-Type: application/json

{
  "issuer": "https://transparency.example/tenant/1234",
  "jwks": {
    "keys": [
      {
        "kid": "urn:ietf:params:oauth\
:jwk-thumbprint:sha-256:DgyowWs04gfVRim5i1WlQ-HFFFKI6Ltqulj1rXPagRo",
        "alg": "ES256",
        "use": "sig",
        "kty": "EC",
        "crv": "P-256",
        "x": "p-kZ4uOASt9IjQRTrWikGnlbGb-z3LU1ltwRjZaOS9w",
        "y": "ymXE1yltJPXgjQSRe9NweN3TLlSUALYZTzy83NVfdg0"
      },
      {
        "kid": "urn:ietf:params:oauth\
:jwk-thumbprint:sha-256:4Fzx5HO1W0ob9CZNc3RJx28Ixpgy9JAFM8jyXKW0ClE",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "use": "enc",
        "kty": "EC",
        "crv": "P-256",
        "x": "Vreuil95vzR6ixutgBBf2ota-rj97MvKfuJWB4qqp5w",
        "y": "NkUTeaoNlLRRsVRxHGDA-RsA0ex2tSpcd3G-4SmKXbs"
      }
    ]
  }
}
~~~

### Request Nonce

This endpoint in inspired by {{-Nonce-Endpoint}}.

Authentication SHOULD NOT be implemented for this endpoint.
This endpoint is used to demonstrate proof of possession, which is the reason that authentication is not required.
Client holding signed statements that require demonstrating proof of possession MUST use this endpoint to obtain a nonce.

Request:

~~~ http-message

GET /nonce HTTP/1.1
Host: transparency.example
Accept: application/json
~~~

Response:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json

{
  "nonce": "d2JhY2NhbG91cmVqdWFuZGFt"
}
~~~

### Resolve Issuer DID

This endpoint enables the use of the DID Web Decentralized Identifier Method, as an alternative expression of the Issuer Metadata endpoint.

This endpoint is DEPRECATED.

The following is a non-normative example of a HTTP request for the Issuer Metadata configuration when `iss` is set to `did:web:transparency.example:tenant:1234`:

Request:

~~~ http-message

GET /tenant/1234/did.json HTTP/1.1
Host: transparency.example
Accept: application/did+ld+json
~~~

Response:

~~~ http-message
HTTP/1.1 200 Ok
Content-Type: application/did+ld+json

{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "@vocab": "https://vocab.transparency.example#"
    }
  ],
  "id": "did:web:transparency.example:tenant:1234",
  "verificationMethod": [
    {
      "id": "did:web:transparency.example:tenant:1234\
        #urn:ietf:params:oauth:jwk-thumbprint\
        :sha-256:5b30k1hBWBMcggA9GIJImUqj4pXqrJ9EOWV6MDdcstA",
      "type": "JsonWebKey",
      "controller": "did:web:transparency.example:tenant:1234",
      "publicKeyJwk": {
        "kid": "urn:ietf:params:oauth:jwk-thumbprint\
          :sha-256:5b30k1hBWBMcggA9GIJImUqj4pXqrJ9EOWV6MDdcstA",
        "alg": "ES256",
        "use": "sig",
        "kty": "EC",
        "crv": "P-256",
        "x": "9ptuW0PBHSTN7bVexWd7xM5kmSPGRaCu-K3SLtJyvNc",
        "y": "l7NvF6QbovicSciZqu_W_xy4JTZwtnUbn2SNdMKoaAk"
      }
    },
    {
      "id": "did:web:transparency.example:tenant:1234\
        #urn:ietf:params:oauth:jwk-thumbprint\
        :sha-256:DgyowWs04gfVRim5i1WlQ-HFFFKI6Ltqulj1rXPagRo",
      "type": "JsonWebKey",
      "controller": "did:web:transparency.example:tenant:1234",
      "publicKeyJwk": {
        "kid": "urn:ietf:params:oauth:jwk-thumbprint\
          :sha-256:DgyowWs04gfVRim5i1WlQ-HFFFKI6Ltqulj1rXPagRo",
        "alg": "ES256",
        "use": "sig",
        "kty": "EC",
        "crv": "P-256",
        "x": "p-kZ4uOASt9IjQRTrWikGnlbGb-z3LU1ltwRjZaOS9w",
        "y": "ymXE1yltJPXgjQSRe9NweN3TLlSUALYZTzy83NVfdg0"
      }
    },
    {
      "id": "did:web:transparency.example:tenant:1234\
        #urn:ietf:params:oauth:jwk-thumbprint\
        :sha-256:4Fzx5HO1W0ob9CZNc3RJx28Ixpgy9JAFM8jyXKW0ClE",
      "type": "JsonWebKey",
      "controller": "did:web:transparency.example:tenant:1234",
      "publicKeyJwk": {
        "kid": "urn:ietf:params:oauth:jwk-thumbprint\
          :sha-256:4Fzx5HO1W0ob9CZNc3RJx28Ixpgy9JAFM8jyXKW0ClE",
        "alg": "HPKE-Base-P256-SHA256-AES128GCM",
        "use": "enc",
        "kty": "EC",
        "crv": "P-256",
        "x": "Vreuil95vzR6ixutgBBf2ota-rj97MvKfuJWB4qqp5w",
        "y": "NkUTeaoNlLRRsVRxHGDA-RsA0ex2tSpcd3G-4SmKXbs"
      }
    }
  ],
  "assertionMethod": [
    "did:web:transparency.example:tenant:1234\
      #urn:ietf:params:oauth:jwk-thumbprint\
      :sha-256:5b30k1hBWBMcggA9GIJImUqj4pXqrJ9EOWV6MDdcstA",
    "did:web:transparency.example:tenant:1234\
      #urn:ietf:params:oauth:jwk-thumbprint\
      :sha-256:DgyowWs04gfVRim5i1WlQ-HFFFKI6Ltqulj1rXPagRo"
  ],
  "authentication": [
    "did:web:transparency.example:tenant:1234\
      #urn:ietf:params:oauth:jwk-thumbprint\
      :sha-256:5b30k1hBWBMcggA9GIJImUqj4pXqrJ9EOWV6MDdcstA",
    "did:web:transparency.example:tenant:1234\
      #urn:ietf:params:oauth:jwk-thumbprint\
      :sha-256:DgyowWs04gfVRim5i1WlQ-HFFFKI6Ltqulj1rXPagRo"
  ],
  "keyAgreement": [
    "did:web:transparency.example:tenant:1234\
      #urn:ietf:params:oauth:jwk-thumbprint\
      :sha-256:4Fzx5HO1W0ob9CZNc3RJx28Ixpgy9JAFM8jyXKW0ClE"
  ]
}
~~~

# Privacy Considerations

TODO

# Security Considerations

TODO

TODO: Consider negotiation for receipt as "JSON" or "YAML".
TODO: Consider impact of media type on "Data URIs" and QR Codes.

# IANA Considerations

## URN Sub-namespace for SCITT (urn:ietf:params:scitt)

IANA is requested to register the URN sub-namespace `urn:ietf:params:scitt`
in the "IETF URN Sub-namespace for Registered Protocol Parameter Identifiers"
Registry {{IANA.params}}, following the template in {{RFC3553}}:

~~~output
   Registry name:  scitt
   Specification:  [RFCthis]
   Repository:  http://www.iana.org/assignments/scitt
   Index value:  No transformation needed.
~~~

## Well-Known URI for Issuers

The following value is requested to be registered in the "Well-Known URIs" registry (using the template from {{RFC5785}}):

URI suffix: issuer
Change controller: IETF
Specification document(s): RFCthis.
Related information: N/A

## Well-Known URI for Transparency Configuration

The following value is requested to be registered in the "Well-Known URIs" registry (using the template from {{RFC5785}}):

URI suffix: transparency-configuration
Change controller: IETF
Specification document(s): RFCthis.
Related information: N/A

TODO: Register them from here.

## Media Type Registration

This section requests registration of the "application/scitt.receipt+cose" media type {{RFC2046}} in the "Media Types" registry in the manner described in {{RFC6838}}.

To indicate that the content is a SCITT Receipt:

- Type name: application
- Subtype name: scitt.receipt+cose
- Required parameters: n/a
- Optional parameters: n/a
- Encoding considerations: TODO
- Security considerations: TODO
- Interoperability considerations: n/a
- Published specification: this specification
- Applications that use this media type: TBD
- Fragment identifier considerations: n/a
- Additional information:
  - Magic number(s): n/a
  - File extension(s): n/a
  - Macintosh file type code(s): n/a
- Person & email address to contact for further information: TODO
- Intended usage: COMMON
- Restrictions on usage: none
- Author: TODO
- Change Controller: IESG
- Provisional registration?  No

--- back
