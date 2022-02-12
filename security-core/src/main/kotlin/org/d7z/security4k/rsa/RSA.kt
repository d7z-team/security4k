package org.d7z.security4k.rsa

import org.d7z.security4k.api.IDataDecoder
import org.d7z.security4k.api.IDataEncoder
import org.d7z.security4k.api.ITextDataCovert
import org.d7z.security4k.base64.Base64Utils
import org.d7z.security4k.utils.foreach
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.Charset
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher

abstract class RSA(
    private val key: String,
    private val keyType: Int,
    protected val signAlgorithm: String,
    private val algorithm: String,
    private val textDataCovert: ITextDataCovert = Base64Utils.simpleBase64,
) : IDataDecoder, IDataEncoder {

    companion object {
        @JvmStatic
        protected val defaultSignAlgorithm: String = "SHA512WithRSA"

        @JvmStatic
        protected val defaultAlgorithm: String = "RSA/ECB/PKCS1Padding"
    }

    // 原始密钥
    protected val rsaKeyData by lazy {
        textDataCovert.decodeToBytes(key)
    }

    private val encryptedBlockSize by lazy { newInitCipher(Cipher.ENCRYPT_MODE).getOutputSize(1) }
    private val maxBlockSize: Int by lazy { encryptedBlockSize - 11 }

    protected val transformation: String = "RSA"

    /**
     * 初始化 Cipher
     *
     * @param mode Int 模式
     * @return Cipher
     */
    private fun newInitCipher(mode: Int): Cipher {
        val cipher = Cipher.getInstance(algorithm)
        val keyFactory = KeyFactory.getInstance(transformation)
        val key = if (keyType == Cipher.PRIVATE_KEY) {
            keyFactory.generatePrivate(PKCS8EncodedKeySpec(rsaKeyData))
        } else {
            keyFactory.generatePublic(X509EncodedKeySpec(rsaKeyData))
        }
        cipher.init(mode, key)
        return cipher
    }

    private fun doFinal(input: InputStream, output: OutputStream, mode: Int, bufferSize: Int) {
        val cipher = newInitCipher(mode)
        val blockOutput = ByteArray(bufferSize * 4)
        input.foreach(bufferSize) { bytes, size ->
            val len = cipher.doFinal(bytes, 0, size, blockOutput)
            output.write(blockOutput, 0, len)
            output.flush()
        }
    }

    override fun decode(cipherStream: InputStream, plainStream: OutputStream) {
        doFinal(cipherStream, plainStream, Cipher.DECRYPT_MODE, encryptedBlockSize)
    }

    override fun encode(plainStream: InputStream, cipherStream: OutputStream) {
        doFinal(plainStream, cipherStream, Cipher.ENCRYPT_MODE, maxBlockSize)
    }

    override fun decodeText(cipherText: String, charset: Charset): String {
        val stream = ByteArrayOutputStream()
        decode(textDataCovert.decodeToBytes(cipherText).inputStream(), stream)
        return stream.toString(charset)
    }

    override fun encodeText(plainText: String, charset: Charset): String {
        val stream = ByteArrayOutputStream()
        encode(plainText.toByteArray(charset).inputStream(), stream)
        return textDataCovert.encodeBytes(stream.toByteArray())
    }
}
