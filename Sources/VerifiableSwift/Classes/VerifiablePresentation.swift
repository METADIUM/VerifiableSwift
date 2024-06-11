//
//  VerifiablePresentation.swift
//  JWS
//
//  Created by 전영배 on 16/08/2019.
//  Copyright © 2019 전영배. All rights reserved.
//

import Foundation
import JWTsSwift

/// Verifiable Presentation
public class VerifiablePresentation : Verifiable, VerifiableDelegator {
    
    
    /// init
    ///
    /// - Throws: VerifiableError.NullType
    public override init() throws {
        try super.init()
        super.delegator = self
    }
    
    
    /// init with json string
    ///
    /// - Parameter json: json string
    /// - Throws: VerifiableError.NullType
    public override init(json: String) throws {
        try super.init(json: json)
        super.delegator = self
    }
    
    /// init with json dictionary
    ///
    /// - Parameter jsonObject: json dictionary
    public override init(jsonObject: [String: Any]) {
        super.init(jsonObject: jsonObject)
        super.delegator = self
    }
    
    
    /// Init with JWS object
    /// - Parameter jws: JWS object of presentation
    /// - Throws: VerifiableError.InvalidPresentation
    public convenience init(jws: JWSObject) throws {
        try self.init()
        
        let jwt = try JWT.init(jsonData: jws.payload)
        let id = jwt.jwtID
        let holder = jwt.issuer
        guard let vpClaims: [String: Any] = jwt.claims["vp"] as? [String: Any] else {
            throw VerifiableError.InvalidPresentation
        }
        
        self.jsonObject = vpClaims
        
        if id != nil {
            self.id = id
        }
        if holder != nil {
            self.holder = holder?.absoluteString
        }
    }
    
    /// Get Type. fixed "VerifiablePresentation"
    ///
    /// - Returns: type
    public override func getType() -> String? {
        return "VerifiablePresentation"
    }
    
    
    /// Add VerifiableCredential
    ///
    /// - Parameter verifiableCredential: verifiable credential
    public func addVerifiableCredential(verifiableCredential: Any) {
        guard var vcList: [Any] = jsonObject["verifiableCredential"] as? [Any] else {
            jsonObject["verifiableCredential"] = [] as [Any]
            addVerifiableCredential(verifiableCredential: verifiableCredential)
            return
        }
        
        vcList.append(verifiableCredential)
        jsonObject["verifiableCredential"] = vcList
    }
    
    
    /// Get list of verifiable credential
    ///
    /// - Returns: array of verifiable credential
    public func verifiableCredentials() -> [Any]? {
        guard let vcList: [Any] = jsonObject["verifiableCredential"] as? [Any] else {
            return nil
        }
        return vcList
    }
    
    
    /// holder
    public var holder: String? {
        set {
            jsonObject["holder"] = newValue
        }
        get {
            return jsonObject["holder"] as? String
        }
    }
    
    
    /// Presentation to JWT
    /// - Parameters:
    ///   - nonce: nonce
    ///   - claims: base claims
    /// - Throws:
    /// - Returns: JWT to formatting
    func toJWT(nonce: String?, claims: JWT?) throws -> JWT {
        let tmpData = try NSKeyedArchiver.archivedData(withRootObject: jsonObject, requiringSecureCoding: true)
        var copiedDict = NSKeyedUnarchiver.unarchiveObject(with: tmpData) as! [String: Any]
        
        let jti = id
        let holder = holder
        
        let jwt = claims == nil ? JWT.init() : claims!
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

}
