package com.github.open_edgn.security4k.asymmetric.rsa

import com.github.open_edgn.security4k.asymmetric.universal.IPublicKey
import com.github.open_edgn.security4k.base64.Base64Utils
import com.github.open_edgn.security4k.utils.foreach
import java.io.InputStream
import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

/**
 * 公钥工具类
 */
class RsaPublic(
    key: String,
    signAlgorithm: String = defaultSignAlgorithm,
    algorithm: String = defaultAlgorithm
) : RSA(key, Cipher.PUBLIC_KEY, signAlgorithm, algorithm), IPublicKey {
    override fun verify(input: InputStream, signText: String, algorithm: String): Boolean {
        val signature = newSignature(algorithm)
        input.foreach { bytes, i ->
            signature.update(bytes, 0, i)
        }
        return signature.verify(Base64Utils.decodeToBytes(signText))
    }

    override fun verify(input: InputStream, signText: String): Boolean {
        return verify(input, signText, signAlgorithm)
    }

    override fun verifyText(data: String, signText: String, algorithm: String, charset: Charset): Boolean {
        return verify(data.toByteArray(charset).inputStream(), signText, algorithm)
    }

    override fun verifyText(data: String, signText: String, charset: Charset): Boolean {
        return verifyText(data, signText, signAlgorithm, charset)
    }

    private fun newSignature(algorithm: String): Signature {
        val keySpec = X509EncodedKeySpec(rsaKeyData)
        val keyFactory = KeyFactory.getInstance(transformation)
        val publicK = keyFactory.generatePublic(keySpec)
        val signature = Signature.getInstance(algorithm)
        signature.initVerify(publicK)
        return signature
    }
}