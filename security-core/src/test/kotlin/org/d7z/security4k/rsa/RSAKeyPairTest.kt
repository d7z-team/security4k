package org.d7z.security4k.rsa

import org.junit.jupiter.api.Test

internal class RSAKeyPairTest {

    private val rsakey = RSAKeyGenerator(1024 * 4)

    @Test
    fun getPublicKeyText() {
        println(rsakey.publicKeyText)
    }

    @Test
    fun getPrivateKeyText() {
        println(rsakey.privateKeyText)
    }
}
