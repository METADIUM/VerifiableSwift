

import XCTest
import VerifiableSwift
import CommonCrypto
import JWTsSwift
import secp256k1

final class VerifiableSwiftTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        return Data(bytes: hash)
    }
    
    func hexString(data: Data) -> String {
        return data.map{ String(format:"%02x", $0) }.joined();
    }
    
    func hexadecimal(hexString: String) -> Data? {
        var data = Data(capacity: hexString.count / 2)
        
        let regex = try! NSRegularExpression(pattern: "[0-9a-f]{1,2}", options: .caseInsensitive)
        regex.enumerateMatches(in: hexString, options: [], range: NSMakeRange(0, hexString.count)) { match, flags, stop in
            let byteString = (hexString as NSString).substring(with: match!.range)
            var num = UInt8(byteString, radix: 16)!
            data.append(&num, count: 1)
        }
        
        guard data.count > 0 else {
            return nil
        }
        
        return data
    }
    
    // Test VerfiableCredential,VerifiablePresentation sign/verify
    func testVcVp() {
        do {
            let currentDate = Date()
            let expireDate = Date() + 60*60
            
            // Make vc
            let vc = try VerifiableCredential.init()
            vc.id = "http://aa.metadium.com/credential/343"
            vc.addTypes(types: ["NameCredential"])
            vc.issuer = "did:meta:3489385543124513254325235432"
            vc.issuanceDate = currentDate
            vc.expirationDate = expireDate
            vc.credentialSubject = ["id": "did:meta:3825783257111111111111111111111111", "name": "mansud"]
            
            // Generate secp256k1 keypair
            guard let privateKey = SECP256K1.generatePrivateKey() else { return XCTAssert(false) }
            guard let publicKey = SECP256K1.privateToPublic(privateKey: privateKey) else { return XCTAssert(false) }
            print("publickey = "+hexString(data: publicKey))
            
            // Signing vc
            let signer = ECDSASigner.init(privateKey: privateKey)
            let signedVC = try vc.sign(kid: "did:meta:387834#ManagementKey#89349348", nonce: "nonce", signer: signer)
            
            // serialize signed vc
            let serializedVC = try signedVC.serialize()
            print("VC = "+serializedVC)
            
            // verify serialized vc
            let verifier = ECDSAVerifier.init(publicKey: publicKey)
            let jws = try JWSObject.init(string: serializedVC)
            guard try jws.verify(verifier: verifier) else {
                XCTAssert(false)
                return
            }
            
            let verifiedVC = try VerifiableCredential.init(jws: jws)
            // Check expiration
            if verifiedVC.expirationDate != nil && verifiedVC.expirationDate! < Date() {
                XCTAssert(false)
                return
            }
            
            XCTAssertEqual(verifiedVC.id, vc.id)
            XCTAssertEqual(verifiedVC.getTypes()?[1], vc.getTypes()?[1])
            XCTAssertEqual(verifiedVC.issuer, vc.issuer)
            XCTAssertEqual(verifiedVC.issuanceDate, vc.issuanceDate)
            XCTAssertEqual(verifiedVC.expirationDate, vc.expirationDate)
            XCTAssertEqual((verifiedVC.credentialSubject as! [String: Any])["id"] as? String, (vc.credentialSubject as! [String: Any])["id"] as? String)
            XCTAssertEqual((verifiedVC.credentialSubject as! [String: Any])["name"] as? String, (vc.credentialSubject as! [String: Any])["name"] as? String)
            // check issuanceDate
            let vcJWT = try JWT.init(jsonData: jws.payload)
            XCTAssertEqual(vcJWT.notBeforeTime, vc.issuanceDate)

            
            // Make VP
            let vp = try VerifiablePresentation.init()
            vp.id = "http://aa.metadium.com/pres/fff"
            vp.holder = "did:meta:38934892431245423523454325423"
            vp.addTypes(types: ["NamePresentation"])
            vp.addVerifiableCredential(verifiableCredential: serializedVC as Any)
            vp.addVerifiableCredential(verifiableCredential: serializedVC as Any)
            
            XCTAssertEqual("http://aa.metadium.com/pres/fff", vp.id)
            XCTAssertEqual("did:meta:38934892431245423523454325423", vp.holder)
            XCTAssertEqual("NamePresentation", vp.getTypes()![1])
            XCTAssertEqual(serializedVC, vp.verifiableCredentials()![0] as! String)
            XCTAssertEqual(serializedVC, vp.verifiableCredentials()![1] as! String)
            
            // Add expiration date
            let jwt = JWT.init()
            jwt.expirationTime = expireDate
            jwt.notBeforeTime = currentDate
            jwt.audience = ["test"]
            
            // Sign vc
            let signedVP = try vp.sign(kid: "did:meta:43894835", nonce: "vp nonce", signer: signer, baseClaims: jwt)
            
            // Serialize signed vp
            let vpString = try signedVP.serialize()
            print("vp = "+vpString)
            
            // Verify serialized vp
            let vpJws = try JWSObject.init(string: vpString)
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
            XCTAssertEqual(UInt64(currentDate.timeIntervalSince1970), UInt64(vpJwt.notBeforeTime!.timeIntervalSince1970))
            XCTAssertEqual(UInt64(expireDate.timeIntervalSince1970), UInt64(vpJwt.expirationTime!.timeIntervalSince1970))
            
            let verifiedVp = try VerifiablePresentation.init(jws: vpJws)
            XCTAssertEqual(verifiedVp.id, vp.id)
            XCTAssertEqual(verifiedVp.holder, vp.holder)
            XCTAssertEqual(verifiedVp.verifiableCredentials()![0] as? String, vp.verifiableCredentials()![0] as? String)
            XCTAssertEqual(verifiedVp.verifiableCredentials()![1] as? String, vp.verifiableCredentials()![1] as? String)
            
            // Verify vc in vp
            for svc in verifiedVp.verifiableCredentials()! {
                let vcJws = try JWSObject.init(string: svc as! String)
                guard try vcJws.verify(verifier: verifier) else {
                    XCTAssert(false)
                    return
                }
            }
        }
        catch {
            print(error.localizedDescription)
            XCTAssert(false)
        }
    }
    
    // Test verify VC from java
    func testExtVcVerify() throws {
        let vcString = "eyJraWQiOiJkaWQ6bWV0YTowMDAwMDM0ODkzODQ5MzI4NTk0MjAjS2V5TWFuYWdlbWVudCM3Mzg3NTg5MjQ3NSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2SyJ9.eyJzdWIiOiJkaWQ6bWV0YToweDExMTExMTExMTIwIiwiaXNzIjoiZGlkOm1ldGE6MHgzNDg5Mzg0OTMyODU5NDIwIiwiZXhwIjoxNTc0OTExNTk4LCJpYXQiOjE1NjYyNzE1OTgsIm5vbmNlIjoiMGQ4bWYwMyIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOlwvXC93M2lkLm9yZ1wvY3JlZGVudGlhbHNcL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJOYW1lQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjoibWFuc3VkIn19LCJqdGkiOiJodHRwOlwvXC9hYS5tZXRhZGl1bS5jb21cL2NyZWRlbnRpYWxcLzM0MyJ9.A9x_gdqPMG3hqzP7yPqouqz4y-HIx4wVjOSGh4oXxufkyQjvQD3uDDmviNv7Xk7F3GXxGg_1hu-nL4cAirjLvA"
        let publicKey = hexadecimal(hexString:"043696d164c46a63ff57498e3e0e6a3d698a2c4f130ea174afd0cfb38b92991e6286c2c3587efac3b9e3cf7e7d5f5af5a048de557d5e976d38e829545b549bcebe")
        
        // Verify VC
        let verifier = ECDSAVerifier.init(publicKey: publicKey!)
        let vcJws = try JWSObject.init(string: vcString)
        guard try vcJws.verify(verifier: verifier) else {
            XCTAssert(false)
            return
        }
        let vc = try VerifiableCredential.init(jws: vcJws)
        let vcJsonString = vc.jsonString()
        print("vc = "+vcJsonString!)
    }
    
    // Text verify VP from java
    func testExtVpVerify() throws {
        guard let publicKey = hexadecimal(hexString: "04b4143b4ea7242687963a804eda9b9b6a16b68e84e23aeeaf0cbde3dfff93239cb8d096654f30c8ea1721b0b86eb058407e21a3897fdd89a7457027559d29e884") else {
            XCTAssert(false)
            return
        }
        guard let vc1PublciKey = hexadecimal(hexString: "0498b6ba68b1aff37640a1cb119846d7a2554d50f9ebcd28d9f594075ac09936a90c5f8fca89b49bca93de945f2c4d572bd185d6d46592a445cc1ad5c5b009211b") else {
            XCTAssert(false)
            return
        }
        guard let vc2PublicKey = hexadecimal(hexString: "042dd6ef966d395c0e92b376ffa98139662c9dc0a0fa7c9ca294248454aa3781d789f4bc5173fef351735cb90737d0d74a7fed93648177684a67a8a7f48f9a7b9d") else {
            XCTAssert(false)
            return
        }
        let vp = "eyJraWQiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAjTWFuYWdlbWVudEtleSM0MzgyNzU4Mjk1IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTZLIn0.eyJpc3MiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczpcL1wvdzNpZC5vcmdcL2NyZWRlbnRpYWxzXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJUZXN0UHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SnJhV1FpT2lKa2FXUTZiV1YwWVRvd01EQXdNRE0wT0Rrek9EUTVNekk0TlRrME1qQWpTMlY1VFdGdVlXZGxiV1Z1ZENNM016ZzNOVGc1TWpRM05TSXNJblI1Y0NJNklrcFhWQ0lzSW1Gc1p5STZJa1ZUTWpVMlN5SjkuZXlKemRXSWlPaUprYVdRNmJXVjBZVG93ZURFeE1URXhNVEV4TVRJd0lpd2lhWE56SWpvaVpHbGtPbTFsZEdFNk1IZ3pORGc1TXpnME9UTXlPRFU1TkRJd0lpd2laWGh3SWpveE5UYzBPVE13TnpNMkxDSnBZWFFpT2pFMU5qWXlPVEEzTXpZc0ltNXZibU5sSWpvaU1HUTRiV1l3TXlJc0luWmpJanA3SWtCamIyNTBaWGgwSWpwYkltaDBkSEJ6T2x3dlhDOTNNMmxrTG05eVoxd3ZZM0psWkdWdWRHbGhiSE5jTDNZeElsMHNJblI1Y0dVaU9sc2lWbVZ5YVdacFlXSnNaVU55WldSbGJuUnBZV3dpTENKT1lXMWxRM0psWkdWdWRHbGhiQ0pkTENKamNtVmtaVzUwYVdGc1UzVmlhbVZqZENJNmV5SnVZVzFsSWpvaWJXRnVjM1ZrSW4xOUxDSnFkR2tpT2lKb2RIUndPbHd2WEM5aFlTNXRaWFJoWkdsMWJTNWpiMjFjTDJOeVpXUmxiblJwWVd4Y0x6TTBNeUo5Lnh2UzJzWk11SXJJZ0g3Rm1DYVVmbk51V3hUeW9YeFJUTFpwdjZNU0toNUxFUFV4M190RnZhOVVtZ2JrQ2xqQzctUloxY2NVUnpfRjJfeGM3UXBrdUZnIiwiZXlKcmFXUWlPaUprYVdRNmJXVjBZVG93TURBd01ETTBPRGt6T0RRNU16STROVGswTWpBalMyVjVUV0Z1WVdkbGJXVnVkQ00zTXpnM05UZzVNalEzTlNJc0luUjVjQ0k2SWtwWFZDSXNJbUZzWnlJNklrVlRNalUyU3lKOS5leUp6ZFdJaU9pSmthV1E2YldWMFlUb3dlREV4TVRFeE1URXhNVEl3SWl3aWFYTnpJam9pWkdsa09tMWxkR0U2TUhnek5EZzVNemcwT1RNeU9EVTVOREl3SWl3aVpYaHdJam94TlRjME9UTXdOelUzTENKcFlYUWlPakUxTmpZeU9UQTNOVGNzSW01dmJtTmxJam9pTUdRNGJXWXdNeUlzSW5aaklqcDdJa0JqYjI1MFpYaDBJanBiSW1oMGRIQnpPbHd2WEM5M00ybGtMbTl5WjF3dlkzSmxaR1Z1ZEdsaGJITmNMM1l4SWwwc0luUjVjR1VpT2xzaVZtVnlhV1pwWVdKc1pVTnlaV1JsYm5ScFlXd2lMQ0pPWVcxbFEzSmxaR1Z1ZEdsaGJDSmRMQ0pqY21Wa1pXNTBhV0ZzVTNWaWFtVmpkQ0k2ZXlKdVlXMWxJam9pYldGdWMzVmtJbjE5TENKcWRHa2lPaUpvZEhSd09sd3ZYQzloWVM1dFpYUmhaR2wxYlM1amIyMWNMMk55WldSbGJuUnBZV3hjTHpNME15SjkuSmtsU1hNMkJvT25kOTN0d3B5WEpuZkpZUmI4Vm1NU1FMNWtkNWNDS0RWdWYxdjNtU2NOeUQwRVhuZ25GX3pRT1dlVjItS2V3VHBQeURXcmhxUmwxTHciXX0sIm5vbmNlIjoiMGQ4bWYwMyIsImp0aSI6Imh0dHA6XC9cL2FhLm1ldGFkaXVtLmNvbVwvcHJlc2VudGF0aW9uXC8zNDMifQ.FW_nEPTRg18D2zaX3ACh1atqlJ1alPMGmNzalmUdloo_bG-DevmkcpMm5yPoKB0uaL_oQLYHb6xvFNNwCRSXig"
        
        // Verify VP
        let verifier = ECDSAVerifier.init(publicKey: publicKey)
        let vpJws = try JWSObject.init(string: vp)
        guard try vpJws.verify(verifier: verifier) else {
            XCTAssert(false)
            return
        }
        
        // Check expiration of VP
        let vpJwt = try JWT.init(jsonData: vpJws.payload)
        if vpJwt.expirationTime != nil && vpJwt.expirationTime! < Date() {
            XCTAssert(false)
            return
        }
        
        let verifiedVP = try VerifiablePresentation.init(jws: vpJws)
        
        guard let vcList = verifiedVP.verifiableCredentials() else {
            XCTAssert(false)
            return
        }
        XCTAssertEqual(vcList.count, 2)
        
        let verifier1 = ECDSAVerifier.init(publicKey: vc1PublciKey)
        let vcJws1 = try JWSObject.init(string: vcList[0] as! String)
        guard try vcJws1.verify(verifier: verifier1) else {
            XCTAssert(false)
            return
        }
        
        let verifier2 = ECDSAVerifier.init(publicKey: vc2PublicKey)
        let vcJws2 = try JWSObject.init(string: vcList[1] as! String)
        guard try vcJws2.verify(verifier: verifier2) else {
            XCTAssert(false)
            return
        }
    }
    
    // Test verify signature from java
    func testExtVerify() {
        guard let publicKey = hexadecimal(hexString: "04489aef20cb7d8435a6011a720fe1301098e597e42f05be5fbe513487e00998c3c739ddbb6915f27743c3e6bf335954952309e2a77f443d84f0eaf751e5f1475e") else {
            XCTAssert(false)
            return
        }
        
        let data = "eyJraWQiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAjTWFuYWdlbWVudEtleSM0MzgyNzU4Mjk1IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTZLIn0.eyJpc3MiOiJkaWQ6bWV0YToweDM0ODkzODQ5MzI4NTk0MjAiLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczpcL1wvdzNpZC5vcmdcL2NyZWRlbnRpYWxzXC92MSJdLCJ0eXBlIjpbIlZlcmlmaWFibGVQcmVzZW50YXRpb24iLCJUZXN0UHJlc2VudGF0aW9uIl0sInZlcmlmaWFibGVDcmVkZW50aWFsIjpbImV5SnJhV1FpT2lKa2FXUTZiV1YwWVRvd2VETTBPRGt6T0RRNU16STROVGswTWpBamEyVjVNU0lzSW5SNWNDSTZJa3BYVkNJc0ltRnNaeUk2SWtWVE1qVTJTeUo5LmV5SnpkV0lpT2lKa2FXUTZiV1YwWVRvd2VERXhNVEV4TVRFeE1USXdJaXdpYVhOeklqb2laR2xrT20xbGRHRTZNSGd6TkRnNU16ZzBPVE15T0RVNU5ESXdJaXdpWlhod0lqb3hOVGN6Tnprd05EUXpMQ0pwWVhRaU9qRTFOalV4TlRBME5ETXNJbTV2Ym1ObElqb2lNR1E0YldZd015SXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9sd3ZYQzkzTTJsa0xtOXlaMXd2WTNKbFpHVnVkR2xoYkhOY0wzWXhJbDBzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSk9ZVzFsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUp1WVcxbElqb2liV0Z1YzNWa0luMTlMQ0pxZEdraU9pSm9kSFJ3T2x3dlhDOWhZUzV0WlhSaFpHbDFiUzVqYjIxY0wyTnlaV1JsYm5ScFlXeGNMek0wTXlKOS5RM2FGNUl1OF81N213OWkxMkRpeVRNOUxBRmlGcWUxRmdYMzVLRHF4YWNJaUlZU1ZGalhuTk1ESndPYmdJMmV6Q014TUVNdEg4ZWVhektnVjRZNzFqZyIsImV5SnJhV1FpT2lKa2FXUTZiV1YwWVRvd2VETTBPRGt6T0RRNU16STROVGswTWpBamEyVjVNU0lzSW5SNWNDSTZJa3BYVkNJc0ltRnNaeUk2SWtWVE1qVTJTeUo5LmV5SnpkV0lpT2lKa2FXUTZiV1YwWVRvd2VERXhNVEV4TVRFeE1USXdJaXdpYVhOeklqb2laR2xrT20xbGRHRTZNSGd6TkRnNU16ZzBPVE15T0RVNU5ESXdJaXdpWlhod0lqb3hOVGN6Tnprd05USTFMQ0pwWVhRaU9qRTFOalV4TlRBMU1qVXNJbTV2Ym1ObElqb2lNR1E0YldZd015SXNJblpqSWpwN0lrQmpiMjUwWlhoMElqcGJJbWgwZEhCek9sd3ZYQzkzTTJsa0xtOXlaMXd2WTNKbFpHVnVkR2xoYkhOY0wzWXhJbDBzSW5SNWNHVWlPbHNpVm1WeWFXWnBZV0pzWlVOeVpXUmxiblJwWVd3aUxDSk9ZVzFsUTNKbFpHVnVkR2xoYkNKZExDSmpjbVZrWlc1MGFXRnNVM1ZpYW1WamRDSTZleUp1WVcxbElqb2liV0Z1YzNWa0luMTlMQ0pxZEdraU9pSm9kSFJ3T2x3dlhDOWhZUzV0WlhSaFpHbDFiUzVqYjIxY0wyTnlaV1JsYm5ScFlXeGNMek0wTXlKOS4yZHFoc0M5cl9XUVRYTW1UamM5N0dsT2Zyc0RDNk81LUtGSTA2dEFac2FHQUdsQ3c4bjRCb0NURlRpYzFsM2VSNEFHd0RvNGpkZ2s2UlVqbDZLSW9LQSJdfSwibm9uY2UiOiIwZDhtZjAzIiwianRpIjoiaHR0cDpcL1wvYWEubWV0YWRpdW0uY29tXC9wcmVzZW50YXRpb25cLzM0MyJ9".data(using: .utf8)
        
        let hash = sha256(data: data!)
        
        print("hash : "+hexString(data: hash))
        
        let serializedSignature = Data.init(base64UrlEncoded: "qMaqkKrL4KBea3uUxxRJpIWh3LMYoukR72o-zS0b-WBewVlqizQ56UK0I4lVvGN68Sv1yletaHcZ9EwiE2eRuQ")!
        
        print("signature : "+hexString(data: serializedSignature))
        
        let verify = SECP256K1.ecdsaVerify(hash: hash, signature: serializedSignature, publicKey: publicKey)
        
        XCTAssert(verify)
    }
    
    
}
