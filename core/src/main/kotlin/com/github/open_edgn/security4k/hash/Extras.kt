@file:Suppress("unused")

package com.github.open_edgn.security4k.hash

import com.github.open_edgn.security4k.hash.HashUtils.METHOD.*
import java.nio.charset.Charset
import java.nio.charset.StandardCharsets.UTF_8


fun String.md5Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, MD5)
fun String.sha1Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, SHA1)
fun String.sha224Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, SHA224)
fun String.sha256Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, SHA256)
fun String.sha384Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, SHA384)
fun String.sha512Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, SHA512)
fun String.crc32Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, CRC32)
fun String.crc32cSum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, CRC32C)


