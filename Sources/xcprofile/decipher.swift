import Foundation

func generateKey(password: String) -> SecKey? {
    let parameters = NSMutableDictionary()
    parameters[kSecAttrKeyType] = kSecAttrKeyTypeAES
    parameters[kSecAttrKeySizeInBits] = SecKeySizes.secAES128.rawValue
    parameters[kSecAttrPRF] = kSecAttrPRFHmacAlgSHA256
    parameters[kSecAttrRounds] = 33333
    parameters[kSecAttrSalt] = password.data(using: .utf8)
    
    return SecKeyDeriveFromPassword(password as NSString, parameters, nil)
}

func transformationCBCForPKCS7(transform: SecTransform, inputData: Data) -> Data {
    SecTransformSetAttribute(transform, kSecEncryptionMode, kSecModeCBCKey, nil)
    SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS7Key, nil)
    SecTransformSetAttribute(transform, kSecTransformInputAttributeName, inputData as CFData, nil)
    
    let output = SecTransformExecute(transform, nil)
    let cfoutput = output as! CFData
    return cfoutput as Data
}

func decipher(key: SecKey, inputData: Data) -> Data? {
    let transform = SecDecryptTransformCreate(key, nil)
    
    return transformationCBCForPKCS7(transform: transform, inputData: inputData)
}

func cipher(key: SecKey, inputData: Data) -> Data? {
    let transform = SecEncryptTransformCreate(key, nil)
    
    return transformationCBCForPKCS7(transform: transform, inputData: inputData)
}

func decipher(data: Data, password: String) -> Data? {
    guard let key = generateKey(password: password) else { return nil }
    return decipher(key: key, inputData: data)
}

func cipher(data: Data, password: String) -> Data? {
    guard let key = generateKey(password: password) else { return nil }
    return cipher(key: key, inputData: data)
}

@discardableResult
func decipher(inputURL: URL, output: URL, password: String) throws -> Bool {
    let inputData = try Data(contentsOf: inputURL)
    guard let outputData = decipher(data: inputData, password: password) else {
        return false
    }
    try outputData.write(to: output, options: .atomic)
    return true
}

@discardableResult
func cipher(inputURL: URL, password: String) throws -> Bool {
    let inputData = try Data(contentsOf: inputURL)
    guard let outputData = cipher(data: inputData, password: password) else {
        return false
    }
    try outputData.write(to: inputURL)
    return true
}
