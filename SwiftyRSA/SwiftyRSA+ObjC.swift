//
//  SwiftyRSA+ObjC.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 3/6/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation

/// This files allows the ObjC runtime to access SwiftyRSA classes while keeping the swift code Swiftyish.
/// Things like protocol extensions or throwing and returning booleans are not well supported by ObjC, so instead
/// of giving access to the Swift classes directly, we're wrapping then their `_objc_*` counterpart.
/// They are exposed under the same name to the ObjC runtime, and all methods are present – they're just delegated
/// to the wrapped swift value.

fileprivate protocol RSA_ObjcBridgeable {
    associatedtype SwiftType
    var swiftValue: SwiftType { get }
    init(swiftValue: SwiftType)
}

// MARK: - PublicKey

@objc(RSAPublicKey)
public class _objc_RSAPublicKey: NSObject, SIGRSA_Key, RSA_ObjcBridgeable { // swiftlint:disable:this type_name
    
    fileprivate let swiftValue: SIGRSA_PublicKey
    
    public var reference: SecKey {
        return swiftValue.reference
    }
    
    public var originalData: Data? {
        return swiftValue.originalData
    }
    
    public func pemString() throws -> String {
        return try swiftValue.pemString()
    }
    
    public func data() throws -> Data {
        return try swiftValue.data()
    }
    
    public func base64String() throws -> String {
        return try swiftValue.base64String()
    }
    
    public required init(swiftValue: SIGRSA_PublicKey) {
        self.swiftValue = swiftValue
    }
    
    required public init(data: Data) throws {
        self.swiftValue = try SIGRSA_PublicKey(data: data)
    }
    
    public required init(reference: SecKey) throws {
        self.swiftValue = try SIGRSA_PublicKey(reference: reference)
    }
    
    public required init(base64Encoded base64String: String) throws {
        self.swiftValue = try SIGRSA_PublicKey(base64Encoded: base64String)
    }
    
    public required init(pemEncoded pemString: String) throws {
        self.swiftValue = try SIGRSA_PublicKey(pemEncoded: pemString)
    }
    
    public required init(pemNamed pemName: String, in bundle: Bundle) throws {
        self.swiftValue = try SIGRSA_PublicKey(pemNamed: pemName, in: bundle)
    }
    
    public required init(derNamed derName: String, in bundle: Bundle) throws {
        self.swiftValue = try SIGRSA_PublicKey(derNamed: derName, in: bundle)
    }
    
    public static func publicKeys(pemEncoded pemString: String) -> [_objc_RSAPublicKey] {
        return SIGRSA_PublicKey.publicKeys(pemEncoded: pemString).map { _objc_RSAPublicKey(swiftValue: $0) }
    }
}

// MARK: - PrivateKey

@objc(RSAPrivateKey)
public class _objc_RSAPrivateKey: NSObject, SIGRSA_Key, RSA_ObjcBridgeable { // swiftlint:disable:this type_name
    
    fileprivate let swiftValue: SIGRSA_PrivateKey
    
    public var reference: SecKey {
        return swiftValue.reference
    }
    
    public var originalData: Data? {
        return swiftValue.originalData
    }
    
    public func pemString() throws -> String {
        return try swiftValue.pemString()
    }
    
    public func data() throws -> Data {
        return try swiftValue.data()
    }
    
    public func base64String() throws -> String {
        return try swiftValue.base64String()
    }
    
    public required init(swiftValue: SIGRSA_PrivateKey) {
        self.swiftValue = swiftValue
    }
    
    public required init(data: Data) throws {
        self.swiftValue = try SIGRSA_PrivateKey(data: data)
    }
    
    public required init(reference: SecKey) throws {
        self.swiftValue = try SIGRSA_PrivateKey(reference: reference)
    }
    
    public required init(base64Encoded base64String: String) throws {
        self.swiftValue = try SIGRSA_PrivateKey(base64Encoded: base64String)
    }
    
    public required init(pemEncoded pemString: String) throws {
        self.swiftValue = try SIGRSA_PrivateKey(pemEncoded: pemString)
    }
    
    public required init(pemNamed pemName: String, in bundle: Bundle) throws {
        self.swiftValue = try SIGRSA_PrivateKey(pemNamed: pemName, in: bundle)
    }
    
    public required init(derNamed derName: String, in bundle: Bundle) throws {
        self.swiftValue = try SIGRSA_PrivateKey(derNamed: derName, in: bundle)
    }
}

// MARK: - VerificationResult

@objc(RSAVerificationResult)
public class _objc_RSAVerificationResult: NSObject { // swiftlint:disable:this type_name
    public let isSuccessful: Bool
    init(isSuccessful: Bool) {
        self.isSuccessful = isSuccessful
    }
}

// MARK: - ClearMessage

@objc(RSAClearMessage)
public class _objc_RSAClearMessage: NSObject, SIGRSA_Message, RSA_ObjcBridgeable { // swiftlint:disable:this type_name
    
    fileprivate let swiftValue: SIGRSA_ClearMessage
    
    public var base64String: String {
        return swiftValue.base64String
    }
    
    public var data: Data {
        return swiftValue.data
    }
    
    public required init(swiftValue: SIGRSA_ClearMessage) {
        self.swiftValue = swiftValue
    }
    
    public required init(data: Data) {
        self.swiftValue = SIGRSA_ClearMessage(data: data)
    }
    
    public required init(string: String, using rawEncoding: UInt) throws {
        let encoding = String.Encoding(rawValue: rawEncoding)
        self.swiftValue = try SIGRSA_ClearMessage(string: string, using: encoding)
    }
    
    public required init(base64Encoded base64String: String) throws {
        self.swiftValue = try SIGRSA_ClearMessage(base64Encoded: base64String)
    }
    
    public func string(encoding: String.Encoding) throws -> String {
        return try swiftValue.string(encoding: encoding)
    }
    
    public func encrypted(with key: _objc_RSAPublicKey, padding: Padding) throws -> _objc_RSAEncryptedMessage {
        let encryptedMessage = try swiftValue.encrypted(with: key.swiftValue, padding: padding)
        return _objc_RSAEncryptedMessage(swiftValue: encryptedMessage)
    }
    
    public func signed(with key: _objc_RSAPrivateKey, digestType: _objc_RSASignature.DigestTypeRSA) throws -> _objc_RSASignature {
        let signature = try swiftValue.signed(with: key.swiftValue, digestType: digestType.swiftValue)
        return _objc_RSASignature(swiftValue: signature)
    }
    
    public func verify(with key: _objc_RSAPublicKey, signature: _objc_RSASignature, digestType: _objc_RSASignature.DigestTypeRSA) throws -> _objc_RSAVerificationResult {
        let isSuccessful = try swiftValue.verify(with: key.swiftValue, signature: signature.swiftValue, digestType: digestType.swiftValue)
        return _objc_RSAVerificationResult(isSuccessful: isSuccessful)
    }
}

// MARK: - EncryptedMessage

@objc(RSAEncryptedMessage)
public class _objc_RSAEncryptedMessage: NSObject, SIGRSA_Message, RSA_ObjcBridgeable { // swiftlint:disable:this type_name
    
    fileprivate let swiftValue: SIGRSA_EncryptedMessage
    
    public var base64String: String {
        return swiftValue.base64String
    }
    
    public var data: Data {
        return swiftValue.data
    }
    
    public required init(swiftValue: SIGRSA_EncryptedMessage) {
        self.swiftValue = swiftValue
    }
    
    public required init(data: Data) {
        self.swiftValue = SIGRSA_EncryptedMessage(data: data)
    }
    
    public required init(base64Encoded base64String: String) throws {
        self.swiftValue = try SIGRSA_EncryptedMessage(base64Encoded: base64String)
    }
    
    public func decrypted(with key: _objc_RSAPrivateKey, padding: Padding) throws -> _objc_RSAClearMessage {
        let clearMessage = try swiftValue.decrypted(with: key.swiftValue, padding: padding)
        return _objc_RSAClearMessage(swiftValue: clearMessage)
    }
}

// MARK: - Signature

@objc(RSASignature)
public class _objc_RSASignature: NSObject, RSA_ObjcBridgeable { // swiftlint:disable:this type_name
    
    @objc
    public enum DigestTypeRSA: Int {
        case sha1
        case sha224
        case sha256
        case sha384
        case sha512
        
        fileprivate var swiftValue: SIGRSA_Signature.DigestTypeRSA {
            switch self {
            case .sha1: return .sha1
            case .sha224: return .sha224
            case .sha256: return .sha256
            case .sha384: return .sha384
            case .sha512: return .sha512
            }
        }
    }
    
    fileprivate let swiftValue: SIGRSA_Signature
    
    public var base64String: String {
        return swiftValue.base64String
    }
    
    public var data: Data {
        return swiftValue.data
    }
    
    public required init(swiftValue: SIGRSA_Signature) {
        self.swiftValue = swiftValue
    }
    
    public init(data: Data) {
        self.swiftValue = SIGRSA_Signature(data: data)
    }
    
    public required init(base64Encoded base64String: String) throws {
        self.swiftValue = try SIGRSA_Signature(base64Encoded: base64String)
    }
}
