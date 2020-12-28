package com.github.open_edgn.security4k.hash

import com.github.open_edgn.security4k.hash.HashUtils.METHOD.*
import org.junit.jupiter.api.Test

import org.junit.jupiter.api.Assertions.*

internal class HashUtilsTest {

    @Test
    fun loadHash() {
        assertEquals(HashUtils.loadHash("String".byteInputStream(Charsets.UTF_8), MD5),"27118326006D3829667A400AD23D5D98")
    }

    @Test
    fun loadTextHash() {
    }

    @Test
    fun asyncLoadHash() {
    }
}