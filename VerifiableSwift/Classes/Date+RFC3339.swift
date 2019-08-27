//
//  Date+RFC3339.swift
//  JWS
//
//  Created by 전영배 on 16/08/2019.
//  Copyright © 2019 전영배. All rights reserved.
//

import Foundation


// MARK: - Supported RFC3339
extension Date {
    
    /// to date
    ///
    /// - Parameter rfc3339String: formated date string. "yyyy-MM-dd'T'HH:mm:ss'Z'"
    /// - Returns: Parsed date
    public static func date(rfc3339String: String) -> Date? {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.date(from: rfc3339String)
    }
    
    
    /// to rfc3339 format string
    ///
    /// - Returns: "yyyy-MM-dd'T'HH:mm:ss'Z'"
    public func rfc3339String() -> String? {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: self)
    }
}
