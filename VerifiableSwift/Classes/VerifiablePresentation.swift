//
//  VerifiablePresentation.swift
//  JWS
//
//  Created by 전영배 on 16/08/2019.
//  Copyright © 2019 전영배. All rights reserved.
//

import Foundation


/// Verifiable Presentation
public class VerifiablePresentation : Verifiable {
    
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
}
