package com.github.open_edgn.security4k.asymmetric.rsa

import com.github.openEdgn.logger4k.getLogger
import com.github.open_edgn.security4k.asymmetric.universal.IPrivateKey
import com.github.open_edgn.security4k.asymmetric.universal.IPublicKey
import com.github.open_edgn.security4k.asymmetric.universal.KeyGenerator
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal class RSATest {
    private val generator: KeyGenerator = RsaKeyGenerator()
    private val publicKey = generator.publicKeyText
    private val privateKey = generator.privateKeyText
    private val privateEncrypt: IPrivateKey = RsaPrivate(privateKey)
    private val publicEncrypt: IPublicKey = RsaPublic(publicKey)
    private val logger = getLogger()

    @Test
    fun testPrivateEncodeToPublicDecode() {
        val plainText = javaClass.getResourceAsStream("/LARGE_TEXT").readAllBytes().toString(Charsets.UTF_8)
        val encodeText = privateEncrypt.encodeText(plainText)
        logger.info("密文：\r\n {}", encodeText)
        val decodeText = publicEncrypt.decodeText(encodeText)
        assertEquals(plainText, decodeText)
    }

    @Test
    fun testPublicEncodeToPrivateDecode() {
        val plainText = javaClass.getResourceAsStream("/SMALL_TEXT").readAllBytes().toString(Charsets.UTF_8)
        val encodeText = publicEncrypt.encodeText(plainText)
        logger.info("密文：\r\n {}", encodeText)
        val decodeText = privateEncrypt.decodeText(encodeText)
        assertEquals(plainText, decodeText)
    }

    @Test
    fun testSignAndVerify() {
        val plainText = javaClass.getResourceAsStream("/SMALL_TEXT").readAllBytes().toString(Charsets.UTF_8)
        val signText = privateEncrypt.signText(plainText)
        logger.info("签名：\r\n {}", signText)
        val verify = publicEncrypt.verifyText(plainText, signText)
        logger.info("校验结果：{}", verify)
        assertTrue(verify)
    }
}