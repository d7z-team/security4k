package com.github.open_edgn.security4k.asymmetric.rsa.old

import com.github.open_edgn.security4k.base64.Base64Utils
import java.io.InputStream
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

class RsaPublicEncrypt(rsaKey: String, maxBlockSize: Int = -1) :
    RsaEncrypt(rsaKey, keyType = Cipher.PUBLIC_KEY, maxBlockSize = maxBlockSize) {

    /**
     * 校验数据签名
     * @param plainData ByteArray
     * @param signText String
     * @param algorithm String
     * @return Boolean
     */
    fun verifyPlainData(plainData: ByteArray, signText: String, algorithm: String = defaultAlgorithm): Boolean {
        val signature = newSignature(algorithm)
        signature.update(plainData)
        return signature.verify(Base64Utils.decodeToBytes(signText))
    }

    /**
     * 校验流签名
     *
     * @param inputStream InputStream
     * @param signText String
     * @param algorithm String
     * @return Boolean
     */
    fun verifyInputStream(inputStream: InputStream, signText: String, algorithm: String = defaultAlgorithm): Boolean {
        val signature = signature(algorithm, inputStream)
        return signature.verify(Base64Utils.decodeToBytes(signText))
    }

     override fun newSignature(algorithm: String): Signature {
        val keySpec = X509EncodedKeySpec(rsaKeyData)
        val keyFactory = KeyFactory.getInstance(transformation)
        val publicK = keyFactory.generatePublic(keySpec)
        val signature = Signature.getInstance(algorithm)
        signature.initVerify(publicK)
        return signature
    }
}