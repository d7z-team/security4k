package org.d7z.security4k.asymmetric.rsa

import org.d7z.security4k.asymmetric.universal.KeyGenerator
import org.d7z.security4k.base64.Base64Utils
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

/**
 *
 * RSA 密钥对生成器
 *
 * **RSA算法非常占用设备性能，谨慎使用**
 *
 * @param keySize Int 密钥对大小
 * @param random SecureRandom 随机数生成器
 * @constructor
 */
class RsaKeyGenerator(
    keySize: Int = 2048,
    random: SecureRandom = SecureRandom.getInstanceStrong()
) : KeyGenerator {
    private var privateKey: RSAPrivateKey
    private var publicKey: RSAPublicKey

    init {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(keySize, random)
        val keyPair = keyPairGen.generateKeyPair()
        publicKey = keyPair.public as RSAPublicKey
        privateKey = keyPair.private as RSAPrivateKey
    }

    override val publicKeyText: String by lazy {
        Base64Utils.encodeBytes(publicKey.encoded, true)
    }

    override val privateKeyText: String by lazy {
        Base64Utils.encodeBytes(privateKey.encoded, true)
    }
}
