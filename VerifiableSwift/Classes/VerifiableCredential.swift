//
//  VerifiableCredential.swift
//  JWS
//
//  Created by 전영배 on 16/08/2019.
//  Copyright © 2019 전영배. All rights reserved.
//

import Foundation
import JWTsSwift

/// VerifiableCredential
public class VerifiableCredential : Verifiable, VerifiableDelegator {
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
    
    
    /// Init with JWSObject
    /// - Parameter jws: jws object of credentail
    /// - Throws: VerifiableError.InvalidCredential
    public convenience init(jws: JWSObject) throws {
        try self.init()
        
        let jwt = try JWT.init(jsonData: jws.payload)
        let id = jwt.jwtID
        let expireDate = jwt.expirationTime
        let issuer = jwt.issuer
        let issuedTime = jwt.notBeforeTime
        let subject = jwt.subject
        guard let vcClaims: [String: Any] = jwt.claims["vc"] as? [String: Any] else {
            throw VerifiableError.InvalidCredential
        }
        
        self.jsonObject = vcClaims
        if id != nil {
            self.id = id
        }
        if expireDate != nil {
            self.expirationDate = expireDate
        }
        if issuer != nil {
            self.issuer = issuer?.absoluteString
        }
        if issuedTime != nil {
            self.issuanceDate = issuedTime
        }
        if subject != nil {
            if self.credentialSubject != nil && self.credentialSubject is [String: Any] {
                var credentialSubject = self.credentialSubject as? [String: Any]
                credentialSubject?["id"] = subject
                self.credentialSubject = credentialSubject
            }
        }
    }
    
    /// Get Type. fixed "VerifiableCredential"
    ///
    /// - Returns: type
    public override func getType() -> String? {
        return "VerifiableCredential"
    }
    
    
    /// issuer
    public var issuer: String? {
        set {
            jsonObject["issuer"] = newValue
        }
        get {
            return jsonObject["issuer"] as? String
        }
    }
    
    
    /// issued date
    public var issuanceDate: Date? {
        set {
            guard let dateString = newValue?.rfc3339String() else {
                return
            }
            jsonObject["issuanceDate"] = dateString
        }
        get {
            guard let date: String = jsonObject["issuanceDate"] as? String else {
                return nil
            }
            return Date.date(rfc3339String: date)
        }
    }
    
    
    /// expire date
    public var expirationDate: Date? {
        set {
            guard let dateString = newValue?.rfc3339String() else {
                return
            }
            jsonObject["expirationDate"] = dateString
        }
        get {
            guard let date: String = jsonObject["expirationDate"] as? String else {
                return nil
            }
            return Date.date(rfc3339String: date)
        }
    }
    
    
    /// credetialSubject
    public var credentialSubject: Any? {
        set {
            jsonObject["credentialSubject"] = newValue
        }
        get {
            return jsonObject["credentialSubject"] as Any
        }
    }
    
    public func getCredentialSubject<T>() -> T? {
        return credentialSubject as? T
    }
    
    /// set credentialStatus
    ///
    /// - Parameters:
    ///   - id: status id
    ///   - type: status type
    public func credentialStatus(id: String, type: String) {
        var cStatus: [String: Any] = [:]
        cStatus["id"] = id
        cStatus["type"] = type
        
        jsonObject["credentailStatus"] = cStatus
    }
    
    
    /// Get id of credentialStatus
    ///
    /// - Returns: id of credentialStatus
    public func getCredentialStatusId() -> String? {
        guard let statusString = jsonObject["credentialStatus"] as? String else {
            guard let statusMap = jsonObject["credentialStatus"] as? [String: Any] else {
                return nil
            }
            return statusMap["id"] as? String
        }
        return statusString
    }
    
    /// Get type of credentialStatus
    ///
    /// - Returns: type of credentialStatus
    public func getCredentialStatusType() -> String? {
        guard let status = jsonObject["credentialStatus"] as? [String: Any] else {
            return nil
        }
        
        return status["type"] as? String
    }
    
    
    /// to json string
    ///
    /// - Returns: json string
    public func jsonString() -> String? {
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: jsonObject, options: [])
            return String(data: jsonData, encoding: .utf8)
        }
        catch {
            return nil;
        }
    }
    
    
    /// VerifiableCredential to JWT
    /// - Parameters:
    ///   - nonce: nonce
    ///   - claims: base JWT claims.
    /// - Throws:
    /// - Returns: JWT to formatting
    func toJWT(nonce: String?, claims: JWT?) throws -> JWT {
        let tmpData = try NSKeyedArchiver.archivedData(withRootObject: jsonObject, requiringSecureCoding: false)
        var copiedDict = NSKeyedUnarchiver.unarchiveObject(with: tmpData) as! [String: Any]
        
        let jti: String? = id
        let expireDate: Date? = expirationDate
        let issuer = issuer
        let issuedDate = issuanceDate
        let credentialSubject = credentialSubject
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
        
        let jwt = claims == nil ? JWT.init() : claims!
        
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
            jwt.notBeforeTime = issuedDate!
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

}
