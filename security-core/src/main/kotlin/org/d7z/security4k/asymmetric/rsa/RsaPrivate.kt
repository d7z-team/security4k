package org.d7z.security4k.asymmetric.rsa

import org.d7z.security4k.asymmetric.universal.IPrivateKey
import org.d7z.security4k.base64.Base64Utils
import org.d7z.security4k.utils.foreach
import java.io.InputStream
import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import javax.crypto.Cipher

/**
 * 私钥工具类
 */
class RsaPrivate(
    key: String,
    signAlgorithm: String = defaultSignAlgorithm,
    algorithm: String = defaultAlgorithm
) :
    org.d7z.security4k.asymmetric.rsa.RSA(key, Cipher.PRIVATE_KEY, signAlgorithm, algorithm), IPrivateKey {
    override fun sign(input: InputStream, algorithm: String): String {
        val signature = newSignature(algorithm)
        input.foreach { bytes, i ->
            signature.update(bytes, 0, i)
        }
        return Base64Utils.encodeBytes(signature.sign())
    }

    override fun sign(input: InputStream): String {
        return sign(input, signAlgorithm)
    }

    override fun signText(data: String, algorithm: String, charset: Charset): String {
        return sign(data.toByteArray(charset).inputStream(), algorithm)
    }

    override fun signText(data: String, charset: Charset): String {
        return signText(data, signAlgorithm, charset)
    }

    private fun newSignature(algorithm: String): Signature {
        val pkcs8KeySpec = PKCS8EncodedKeySpec(rsaKeyData)
        val keyFactory = KeyFactory.getInstance(transformation)
        val privateK = keyFactory.generatePrivate(pkcs8KeySpec)
        val signature = Signature.getInstance(algorithm)
        signature.initSign(privateK)
        return signature
    }
}
