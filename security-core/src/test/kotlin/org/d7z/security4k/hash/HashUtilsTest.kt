package org.d7z.security4k.hash

import org.d7z.security4k.hash.HashUtils.METHOD.* // ktlint-disable no-wildcard-imports
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class HashUtilsTest {
    private val resource = HashUtils.javaClass.getResource("/HASH")

    @Test
    fun loadHash() {
        assertEquals(HashUtils.loadHash(resource.openStream(), MD5), "98C37608A93DFF7E27035A76608F2EB1")
        assertEquals(HashUtils.loadHash(resource.openStream(), SHA1), "43F193350BA0A730E8193863601D22F4C61EA21B")
        assertEquals(
            HashUtils.loadHash(resource.openStream(), SHA256),
            "8DF21652A2C552D7E442B8A1FAEC71F8A12B71EAB72F582C1F67B330792561C3"
        )
        assertEquals(
            HashUtils.loadHash(resource.openStream(), SHA384),
            "FB7BB3DB1DD16FC0FA60EAF8AE50F54B1146848382018F7E9BC42621AF28C6035B2CD085A65AEA0344C87451C50EF2D4"
        )
        assertEquals(
            HashUtils.loadHash(resource.openStream(), SHA512),
            "268DBCBFABF0547DDD83B9141358AA82517FDA3A41BFFCBBE035237128A1187CC052A457E4D0C34646FB740A5BE5185CE0B85B35490FE6E910CE67586048DE93"
        )
        assertEquals(HashUtils.loadHash(resource.openStream(), CRC32), "992D6F49")
    }

    @Test
    fun loadTextHash() {
        val data = resource.openStream().readAllBytes().toString(Charsets.UTF_8)
        assertEquals(HashUtils.loadTextHash(data, method = MD5), "98C37608A93DFF7E27035A76608F2EB1")
        assertEquals(HashUtils.loadTextHash(data, method = SHA1), "43F193350BA0A730E8193863601D22F4C61EA21B")
        assertEquals(
            HashUtils.loadTextHash(data, method = SHA256),
            "8DF21652A2C552D7E442B8A1FAEC71F8A12B71EAB72F582C1F67B330792561C3"
        )
        assertEquals(
            HashUtils.loadTextHash(data, method = SHA384),
            "FB7BB3DB1DD16FC0FA60EAF8AE50F54B1146848382018F7E9BC42621AF28C6035B2CD085A65AEA0344C87451C50EF2D4"
        )
        assertEquals(
            HashUtils.loadTextHash(data, method = SHA512),
            "268DBCBFABF0547DDD83B9141358AA82517FDA3A41BFFCBBE035237128A1187CC052A457E4D0C34646FB740A5BE5185CE0B85B35490FE6E910CE67586048DE93"
        )
        assertEquals(HashUtils.loadTextHash(data, method = CRC32), "992D6F49")
    }

    @Test
    fun asyncLoadHash() {
        HashUtils.asyncLoadHash(resource.openStream(), MD5) {
            assertEquals(it, "98C37608A93DFF7E27035A76608F2EB1")
        }
        Thread.sleep(500)
    }
}
