//
//  Verifiable.swift
//  JWS
//
//  Created by 전영배 on 16/08/2019.
//  Copyright © 2019 전영배. All rights reserved.
//

import Foundation
import JWTsSwift


/// JWT 로 변환할 delegator
protocol VerifiableDelegator {
    func toJWT(nonce: String?, claims: JWT?) throws -> JWT
}

/// Verifiable error
///
/// - NullType: type is null. Need override func getType()
/// - InvalidCredential: invalid credentail
/// - InvalidCredential: invalid presentation
enum VerifiableError: Error {
    case NullType
    case InvalidCredential
    case InvalidPresentation
    case Unknown
}


/// Verifiable. [VerifiableCredential, VerifiablePresentation]
public class Verifiable {
    
    /// verifiable data
    var jsonObject: [String: Any]
    
    var delegator: VerifiableDelegator?
    
    
    /// init
    ///
    /// - Throws: VerifiableError.NullType
    public init() throws {
        jsonObject = [:]
        
        // Add base context
        let context = ["https://www.w3.org/2018/credentials/v1"]
        jsonObject["@context"] = context
        
        // Set type
        guard let type = getType() else {
            throw VerifiableError.NullType
        }
        let typeArray = [type]
        jsonObject["type"] = typeArray
    }
    
    
    /// init with json string
    ///
    /// - Parameter json: json string
    /// - Throws: json serializing error
    public init(json: String) throws {
        self.jsonObject = try JSONSerialization.jsonObject(with: json.data(using: .utf8)!, options: []) as! [String: Any]
    }
    
    
    /// init with json dictionary
    ///
    /// - Parameter jsonObject: json dictionary
    public init(jsonObject: [String: Any]) {
        self.jsonObject = jsonObject
    }
    
    
    /// type. Need override getType() func
    ///
    /// - Returns: type
    public func getType() -> String? {
        return nil;
    }
    
    
    /// Add list of context
    ///
    /// - Parameter contexts: array of context to add
    public func addContexts(contexts: [String]) {
        guard var contextList: [String] = jsonObject["@context"] as? [String] else {
            return
        }
        contextList.append(contentsOf: contexts)
    }
    
    
    /// Get list of context
    ///
    /// - Returns: array of context
    public func getContexts() -> [String]? {
        return jsonObject["@context"] as? [String]
    }
    
    
    /// id
    public var id: String? {
        set {
            jsonObject["id"] = newValue
        }
        get {
            return jsonObject["id"] as? String
        }
    }
    
    
    /// Add type
    ///
    /// - Parameter types: type name
    public func addTypes(types: [String]) {
        guard var typeList: [String] = jsonObject["type"] as? [String] else {
            return
        }
        typeList.append(contentsOf: types)
        jsonObject["type"] = typeList
    }
    
    
    /// Get list of type
    ///
    /// - Returns: array of type
    public func getTypes() -> [String]? {
        return jsonObject["type"] as? [String]
    }
    
    
    /// proof
    public var proof: String? {
        set {
            jsonObject["proof"] = newValue
        }
        get {
            return jsonObject["proof"] as? String
        }
    }
    
    
    /// Get json data
    ///
    /// - Returns: json dictionary
    public func getJson() -> [String: Any] {
        return jsonObject
    }
    
    
    /// Sign credential or presentation
    /// - Parameters:
    ///   - algorithm: signature algorithm
    ///   - kid: key id
    ///   - nonce: nonce
    ///   - signer: JWS signer
    ///   - baseClaims: base JWT claims. presentation 에 issuanceDate, expirationDate 추가사 사용
    /// - Throws: error to sign
    /// - Returns: signed jws
    public func sign(algorithm: SignatureAlgorithm, kid: String, nonce: String?, signer: JWSSigner, baseClaims: JWT?) throws -> JWSObject {
        // To JWT
        guard let jsonData = try delegator?.toJWT(nonce: nonce, claims: baseClaims).data() else {
            throw VerifiableError.Unknown
        }

        // Sign JWT
        let header: JWSHeader = JWSHeader.init(algorithm: algorithm)
        header.kid = kid
        let jws:JWSObject = JWSObject.init(header: header, payload: jsonData)
        try jws.sign(signer: signer)
        
        return jws
    }
    
    
    /// Sign credential or presentation. algorithm is ES256K
    /// - Parameters:
    ///   - kid: key id
    ///   - nonce: nonce
    ///   - signer: JWS signer
    ///   - baseClaims: base JWT claims. presentation 에 issuanceDate, expirationDate 추가사 사용
    /// - Throws: error to sign
    /// - Returns: signed jws
    public func sign(kid: String, nonce: String?, signer: JWSSigner, baseClaims: JWT?) throws -> JWSObject {
        return try sign(algorithm: .ES256K, kid: kid, nonce: nonce, signer: signer, baseClaims: baseClaims)
    }

    /// Sign credential or presentation. . algorithm is ES256K
    /// - Parameters:
    ///   - kid: key id
    ///   - nonce: nonce
    ///   - signer: JWS signer
    /// - Throws: error to sign
    /// - Returns: signed jws
    public func sign(kid: String, nonce: String?, signer: JWSSigner) throws -> JWSObject {
        return try sign(kid: kid, nonce: nonce, signer: signer, baseClaims: nil)
    }

}
