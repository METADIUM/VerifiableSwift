//
//  VerifiableJWTSignerAndVerifier.swift
//  JWS
//
//  Created by 전영배 on 16/08/2019.
//  Copyright © 2019 전영배. All rights reserved.
//

import Foundation
import JWTsSwift

/// Sign and verify Verifiable(Credential/Presentation)
@available(*, deprecated, message:"use Verifiable, VerifiableCredential, VerifiablePresentation instead")
public class VerifiableSignVerifier {
    
    public init() {
    }
    
    /// Sign credential or presentation
    ///
    /// - Parameters:
    ///   - verifiable: credential or presentation
    ///   - algorithm: signature algorithm
    ///   - kid: key id of private key to sign
    ///   - nonce: nonce to replay attack
    ///   - signer: to use sign
    /// - Returns: Signed JWT
    /// - Throws: failed sign
    public func sign(verifiable: Verifiable, algorithm: SignatureAlgorithm, kid: String, nonce: String?, signer: JWSSigner) throws -> JWSObject? {
        var jsonData: Data
        if verifiable is VerifiableCredential {
            try jsonData = toJWT(vc: verifiable as! VerifiableCredential, nonce: nonce).data()
        }
        else if verifiable is VerifiablePresentation {
            try jsonData = toJWT(vp: verifiable as! VerifiablePresentation, nonce: nonce).data()
        }
        else {
            return nil
        }
        
        let header: JWSHeader = JWSHeader.init(algorithm: .ES256K)
        header.kid = kid
        let jws:JWSObject = JWSObject.init(header: header, payload: jsonData)
        
        try jws.sign(signer: signer)
        
        return jws
    }
    
    
    /// Verify credential or presentation
    ///
    /// - Parameters:
    ///   - serializedVerifiable: signed JWT of credential or presentation
    ///   - verifier: to verify
    /// - Returns: VerifiableCredential or VerifablePresentation
    /// - Throws: failed verify
    public func verify(serializedVerifiable: String, verifier: JWSVerifier) throws -> Verifiable? {
        let jws = try JWSObject.init(string: serializedVerifiable)
        guard try jws.verify(verifier: verifier) else {
            return nil
        }
        
        let jwt = try JWT.init(jsonData: jws.payload)
        if jwt.claims["vc"] != nil {
            return try toCredential(jwt: jwt)
        }
        else if jwt.claims["vp"] != nil {
            return try toPresentation(jwt: jwt)
        }
        
        return nil
    }
    
    
    /// Convert verifiable credential to JWT
    ///
    /// - Parameters:
    ///   - vc: verifiable crendentail
    ///   - nonce: to replay attack
    /// - Returns: JWT
    /// - Throws: converting failed
    private func toJWT(vc: VerifiableCredential, nonce: String?) throws -> JWT {
        let tmpData = try NSKeyedArchiver.archivedData(withRootObject: vc.jsonObject, requiringSecureCoding: false)
        var copiedDict = NSKeyedUnarchiver.unarchiveObject(with: tmpData) as! [String: Any]
        
        let jti: String? = vc.id
        let expireDate: Date? = vc.expirationDate
        let issuer = vc.issuer
        let issuedDate = vc.issuanceDate
        let credentialSubject = vc.credentialSubject
        var subject: String? = nil
        if credentialSubject is [String: Any] {
            let id = (credentialSubject as! [String: Any])["id"] as? String
            if id != nil {
                subject = id
                var tmp: [String: Any] = copiedDict["credentialSubject"] as! [String: Any]
                tmp.removeValue(forKey: "id")
                copiedDict["credentialSubject"] = tmp
            }
        }
        
        let jwt = JWT.init()
        if jti != nil {
            copiedDict.removeValue(forKey: "id")
            jwt.jwtID = jti!
        }
        if expireDate != nil {
            copiedDict.removeValue(forKey: "expirationDate")
            jwt.expirationTime = expireDate!
        }
        if issuer != nil {
            copiedDict.removeValue(forKey: "issuer")
            jwt.issuer = URL.init(string: issuer!)
        }
        if issuedDate != nil {
            copiedDict.removeValue(forKey: "issuanceDate")
            jwt.issuedAt = issuedDate!
        }
        if subject != nil {
            jwt.subject = subject!
        }
        if nonce != nil {
            jwt.claims["nonce"] = nonce
        }
        jwt.claims["vc"] = copiedDict
        
        
        return jwt
    }
    
    
    /// Convert verifiable presentation to JWT
    ///
    /// - Parameters:
    ///   - vp: verifiable presentation
    ///   - nonce: to replay attack
    /// - Returns: JWT
    /// - Throws: converting failed
    private func toJWT(vp: VerifiablePresentation, nonce: String?) throws -> JWT {
        let tmpData = try NSKeyedArchiver.archivedData(withRootObject: vp.jsonObject, requiringSecureCoding: true)
        var copiedDict = NSKeyedUnarchiver.unarchiveObject(with: tmpData) as! [String: Any]
        
        let jti = vp.id
        let holder = vp.holder
        
        let jwt = JWT.init()
        if jti != nil {
            copiedDict.removeValue(forKey: "id")
            jwt.jwtID = jti!
        }
        if holder != nil {
            copiedDict.removeValue(forKey: "holder")
            jwt.issuer = URL.init(string: holder!)
        }
        if nonce != nil {
            jwt.claims["nonce"] = nonce
        }
        jwt.claims["vp"] = copiedDict
        
        return jwt
    }
    
    
    /// Convert JWT to verifiable credential
    ///
    /// - Parameter jwt: JWT
    /// - Returns: JWT is not exist "vc" claim, return nil
    /// - Throws: Converting failed
    private func toCredential(jwt: JWT) throws -> VerifiableCredential? {
        let id = jwt.jwtID
        let expireDate = jwt.expirationTime
        let issuer = jwt.issuer
        let issuedTime = jwt.issuedAt
        let subject = jwt.subject
        guard let vcClaims: [String: Any] = jwt.claims["vc"] as? [String: Any] else {
            return nil
        }
        
        let vc = VerifiableCredential.init(jsonObject: vcClaims)
        if id != nil {
            vc.id = id
        }
        if expireDate != nil {
            vc.expirationDate = expireDate
        }
        if issuer != nil {
            vc.issuer = issuer?.absoluteString
        }
        if issuedTime != nil {
            vc.issuanceDate = issuedTime
        }
        if subject != nil {
            if vc.credentialSubject != nil && vc.credentialSubject is [String: Any] {
                var credentialSubject = vc.credentialSubject as? [String: Any]
                credentialSubject?["id"] = subject
                vc.credentialSubject = credentialSubject
            }
        }
        
        return vc
    }
    
    
    /// Convert JWT to verifiable credential
    ///
    /// - Parameter jwt: JWT
    /// - Returns: JWT is not exist "vp" claim, return nil
    /// - Throws: Converting failed
    private func toPresentation(jwt: JWT) throws -> VerifiablePresentation? {
        let id = jwt.jwtID
        let holder = jwt.issuer
        guard let vpClaims: [String: Any] = jwt.claims["vp"] as? [String: Any] else {
            return nil
        }
        
        let vp = VerifiablePresentation.init(jsonObject: vpClaims)
        if id != nil {
            vp.id = id
        }
        if holder != nil {
            vp.holder = holder?.absoluteString
        }
        
        return vp
    }
}
