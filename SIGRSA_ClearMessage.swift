//
//  ClearMessage.swift
//  SwiftyRSA
//
//  Created by Lois Di Qual on 5/18/17.
//  Copyright © 2017 Scoop. All rights reserved.
//

import Foundation
import CommonCrypto

public class SIGRSA_ClearMessage: SIGRSA_Message {
    
    /// Data of the message
    public let data: Data
    
    /// Creates a clear message with data.
    ///
    /// - Parameter data: Data of the clear message
    public required init(data: Data) {
        self.data = data
    }
    
    /// Creates a clear message from a string, with the specified encoding.
    ///
    /// - Parameters:
    ///   - string: String value of the clear message
    ///   - encoding: Encoding to use to generate the clear data
    /// - Throws: SIGRSA_SwiftyRSAError
    public convenience init(string: String, using encoding: String.Encoding) throws {
        guard let data = string.data(using: encoding) else {
            throw SIGRSA_SwiftyRSAError.stringToDataConversionFailed
        }
        self.init(data: data)
    }
    
    /// Returns the string representation of the clear message using the specified
    /// string encoding.
    ///
    /// - Parameter encoding: Encoding to use during the string conversion
    /// - Returns: String representation of the clear message
    /// - Throws: SIGRSA_SwiftyRSAError
    public func string(encoding: String.Encoding) throws -> String {
        guard let str = String(data: data, encoding: encoding) else {
            throw SIGRSA_SwiftyRSAError.dataToStringConversionFailed
        }
        return str
    }
    
    /// Encrypts a clear message with a public key and returns an encrypted message.
    ///
    /// - Parameters:
    ///   - key: Public key to encrypt the clear message with
    ///   - padding: Padding to use during the encryption
    /// - Returns: Encrypted message
    /// - Throws: SIGRSA_SwiftyRSAError
    public func encrypted(with key: SIGRSA_PublicKey, padding: Padding) throws -> SIGRSA_EncryptedMessage {
        
        let blockSize = SecKeyGetBlockSize(key.reference)
        let maxChunkSize = (padding == []) ? blockSize : blockSize - 11
        
        var decryptedDataAsArray = [UInt8](repeating: 0, count: data.count)
        (data as NSData).getBytes(&decryptedDataAsArray, length: data.count)
        
        var encryptedDataBytes = [UInt8](repeating: 0, count: 0)
        var idx = 0
        while idx < decryptedDataAsArray.count {
            
            let idxEnd = min(idx + maxChunkSize, decryptedDataAsArray.count)
            let chunkData = [UInt8](decryptedDataAsArray[idx..<idxEnd])
            
            var encryptedDataBuffer = [UInt8](repeating: 0, count: blockSize)
            var encryptedDataLength = blockSize
            
            let status = SecKeyEncrypt(key.reference, padding, chunkData, chunkData.count, &encryptedDataBuffer, &encryptedDataLength)
            
            guard status == noErr else {
                throw SIGRSA_SwiftyRSAError.chunkEncryptFailed(index: idx)
            }
            
            encryptedDataBytes += encryptedDataBuffer
            
            idx += maxChunkSize
        }
        
        let encryptedData = Data(bytes: UnsafePointer<UInt8>(encryptedDataBytes), count: encryptedDataBytes.count)
        return SIGRSA_EncryptedMessage(data: encryptedData)
    }
    
    /// Signs a clear message using a private key.
    /// The clear message will first be hashed using the specified digest type, then signed
    /// using the provided private key.
    ///
    /// - Parameters:
    ///   - key: Private key to sign the clear message with
    ///   - digestType: Digest
    /// - Returns: Signature of the clear message after signing it with the specified digest type.
    /// - Throws: SIGRSA_SwiftyRSAError
    public func signed(with key: SIGRSA_PrivateKey, digestType: SIGRSA_Signature.DigestTypeRSA) throws -> SIGRSA_Signature {
        
        let digest = self.digest(digestType: digestType)
        let blockSize = SecKeyGetBlockSize(key.reference)
        let maxChunkSize = blockSize - 11
        
        guard digest.count <= maxChunkSize else {
            throw SIGRSA_SwiftyRSAError.invalidDigestSize(digestSize: digest.count, maxChunkSize: maxChunkSize)
        }
        
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: blockSize)
        var signatureDataLength = blockSize
        
        let status = SecKeyRawSign(key.reference, digestType.padding, digestBytes, digestBytes.count, &signatureBytes, &signatureDataLength)
        
        guard status == noErr else {
            throw SIGRSA_SwiftyRSAError.signatureCreateFailed(status: status)
        }
        
        let signatureData = Data(bytes: UnsafePointer<UInt8>(signatureBytes), count: signatureBytes.count)
        return SIGRSA_Signature(data: signatureData)
    }
    
    /// Verifies the signature of a clear message.
    ///
    /// - Parameters:
    ///   - key: Public key to verify the signature with
    ///   - signature: Signature to verify
    ///   - digestType: Digest type used for the signature
    /// - Returns: Result of the verification
    /// - Throws: SIGRSA_SwiftyRSAError
    public func verify(with key: SIGRSA_PublicKey, signature: SIGRSA_Signature, digestType: SIGRSA_Signature.DigestTypeRSA) throws -> Bool {
        
        let digest = self.digest(digestType: digestType)
        var digestBytes = [UInt8](repeating: 0, count: digest.count)
        (digest as NSData).getBytes(&digestBytes, length: digest.count)
        
        var signatureBytes = [UInt8](repeating: 0, count: signature.data.count)
        (signature.data as NSData).getBytes(&signatureBytes, length: signature.data.count)
        
        let status = SecKeyRawVerify(key.reference, digestType.padding, digestBytes, digestBytes.count, signatureBytes, signatureBytes.count)
        
        if status == errSecSuccess {
            return true
        } else if status == -9809 {
            return false
        } else {
            throw SIGRSA_SwiftyRSAError.signatureVerifyFailed(status: status)
        }
    }
    
    func digest(digestType: SIGRSA_Signature.DigestTypeRSA) -> Data {
        switch digestType {
        case .sha1:
            return data.sha1()
        case .sha224:
            return data.sha224()
        case .sha256:
            return data.sha256()
        case .sha384:
            return data.sha384()
        case .sha512:
            return data.sha512()
        }
    }
}

extension Data {
    func sha1() -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA1_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(self.count), &digest)
        }
        
        return NSData(bytes: &digest, length:Int(CC_SHA1_DIGEST_LENGTH)) as Data
    }
    func sha224() -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA224_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA224($0.baseAddress, CC_LONG(self.count), &digest)
        }
        return NSData(bytes: &digest, length:Int(CC_SHA224_DIGEST_LENGTH)) as Data

    }
    func sha256() -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA256_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(self.count), &digest)
        }
        return NSData(bytes: &digest, length:Int(CC_SHA256_DIGEST_LENGTH)) as Data

    }
    func sha384() -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA384_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA384($0.baseAddress, CC_LONG(self.count), &digest)
        }
        return NSData(bytes: &digest, length:Int(CC_SHA384_DIGEST_LENGTH)) as Data

    }
    func sha512() -> Data {
        var digest = [UInt8](repeating: 0, count:Int(CC_SHA512_DIGEST_LENGTH))
        self.withUnsafeBytes {
            _ = CC_SHA512($0.baseAddress, CC_LONG(self.count), &digest)
        }
        return NSData(bytes: &digest, length:Int(CC_SHA512_DIGEST_LENGTH)) as Data

    }
}

