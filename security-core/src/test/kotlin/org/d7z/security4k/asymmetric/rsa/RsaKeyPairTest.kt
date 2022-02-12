package org.d7z.security4k.asymmetric.rsa

import org.junit.jupiter.api.Test

internal class RsaKeyPairTest {

    private val rsakey = RsaKeyGenerator(1024 * 4)
    @Test
    fun getPublicKeyText() {
        println(rsakey.publicKeyText)
    }

    @Test
    fun getPrivateKeyText() {
        println(rsakey.privateKeyText)
    }
}
