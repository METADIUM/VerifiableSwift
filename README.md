# VerifiableSwift

[![CI Status](https://img.shields.io/travis/METADIUM/VerifiableSwift.svg?style=flat)](https://travis-ci.org/METADIUM/VerifiableSwift)
[![Version](https://img.shields.io/cocoapods/v/VerifiableSwift.svg?style=flat)](https://cocoapods.org/pods/VerifiableSwift)
[![License](https://img.shields.io/cocoapods/l/VerifiableSwift.svg?style=flat)](https://cocoapods.org/pods/VerifiableSwift)
[![Platform](https://img.shields.io/cocoapods/p/VerifiableSwift.svg?style=flat)](https://cocoapods.org/pods/VerifiableSwift)

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.

## Requirements

## Installation

VerifiableSwift is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'VerifiableSwift'
```
## Usage

### Sign Credential

Create and sign Credential

```swift
// Load did info
let did = "did:meta:000000000000000000000000000000000000000000000000000000000000054b"
let keyId = "did:meta:000000000000000000000000000000000000000000000000000000000000054b#ManagementKey#cfd31afff25b2260ea15ef59f2d5d7dfe8c13511"
let privateKey = ...

// Create credential
let vc = try VerifiableCredential.init()
vc.id = "http://aa.metadium.com/credential/343"
vc.addTypes(types: ["NameCredential"])
vc.issuer = did
vc.issuanceDate = Date()
vc.expirationDate = Date() + 365*24*60*60
vc.credentialSubject = ["id": "did:meta:0000000000000000000000000000000000000000000000000000000000012530", "name": "mansud"]


// Signing credential to JSON web token
let signer = ECDSASigner.init(privateKey: privateKey)
let signedVC = try vc.sign(kid: keyId, nonce: "nonce", signer: signer)

// Serialize signed vc
let serializedVC = try signedVC.serialize()
```

### Sign Presentation

Create and sign presentation

```swift
// Load did info
let did = "did:meta:0000000000000000000000000000000000000000000000000000000000012530"
let keyId = "did:meta:0000000000000000000000000000000000000000000000000000000000012530#ManagementKey#c82bd0c7893c267821b7d727c9583c88337aa32d"
let privateKey = ...


// Create presentation
let vp = try VerifiablePresentation.init()
vp.id = "http://aa.metadium.com/pres/fff"
vp.holder = did
vp.addTypes(types: ["NamePresentation"])
vp.addVerifiableCredential(verifiableCredential: serializedVC as Any)

// Signing credential to JSON web token
let signedVP = try vp.sign(kid: "did:meta:43894835", nonce: "vp nonce", signer: signer)

// Serialize signed vp
let serializedVP = try signedVP.serialize()
```

Add issuance and expiration date in presentation

```swift
// Add expiration date
let jwt = JWT.init()
jwt.notBeforeTime = Date()
jwt.expirationTime = Date() + 365*24*60*60

// Signing credential to JSON web token
let signedVP = try vp.sign(kid: "did:meta:43894835", nonce: "vp nonce", signer: signer, baseClaims: jwt)
```

### Verify Credential

Verify credential received from issuer. 

```swift
// public key of issuer
let publicKey = ...

// credential recevied from issuer
let serializedVC = ...

// verify serialized vc
let verifier = ECDSAVerifier.init(publicKey: publicKey)
let jws = try JWSObject.init(string: serializedVC)
guard try jws.verify(verifier: verifier) else {
    return
}

// Check expiration
let verifiedVC = try VerifiableCredential.init(jws: jws)
if verifiedVC.expirationDate != nil && verifiedVC.expirationDate! < Date() {
    return
}

// Get claim
let nameClaim = verifiedVC.credentialSubject as! [String: Any])["name"] as? String
```

### Verify presentation

Verify presentation received from holder

```swift
// public key of holder
let publicKey = ...

// presentation recevied from holder
let serializedVP = ...


// Verify serialized vp
let verifier = ECDSAVerifier.init(publicKey: publicKey)
let vpJws = try JWSObject.init(string: serializedVP)
guard try vpJws.verify(verifier: verifier) else {
    XCTAssert(false)
    return
}
// Check expiration
let vpJwt = try JWT.init(jsonData: vpJws.payload)
if vpJwt.expirationTime != nil && vpJwt.expirationTime! < Date() {
    XCTAssert(false)
    return
}

// Get credentials
let verifiedVp = try VerifiablePresentation.init(jws: vpJws)
let credentials = verifiedVp.verifiableCredentials()!
```



## Author

ybjeon@coinplug.com

## License

VerifiableSwift is available under the MIT license. See the LICENSE file for more info.
