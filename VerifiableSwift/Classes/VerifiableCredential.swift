//
//  VerifiableCredential.swift
//  JWS
//
//  Created by 전영배 on 16/08/2019.
//  Copyright © 2019 전영배. All rights reserved.
//

import Foundation


/// VerifiableCredential
public class VerifiableCredential : Verifiable {
    
    
    /// init
    ///
    /// - Throws: VerifiableError.NullType
    public override init() throws {
        try super.init()
    }
    
    
    /// init with json string
    ///
    /// - Parameter json: json string
    /// - Throws: VerifiableError.NullType
    public override init(json: String) throws {
        try super.init(json: json)
    }
    
    
    /// init with json dictionary
    ///
    /// - Parameter jsonObject: json dictionary
    public override init(jsonObject: [String: Any]) {
        super.init(jsonObject: jsonObject)
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
}
