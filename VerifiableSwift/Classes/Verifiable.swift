//
//  Verifiable.swift
//  JWS
//
//  Created by 전영배 on 16/08/2019.
//  Copyright © 2019 전영배. All rights reserved.
//

import Foundation


/// Verifiable error
///
/// - NullType: type is null. Need override func getType()
enum VerifiableError: Error {
    case NullType
}


/// Verifiable. [VerifiableCredential, VerifiablePresentation]
public class Verifiable {
    
    /// verifiable data
    var jsonObject: [String: Any]
    
    
    /// init
    ///
    /// - Throws: VerifiableError.NullType
    public init() throws {
        jsonObject = [:]
        
        // Add base context
        let context = ["http://w3id.org/credentials/v1"]
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
}
