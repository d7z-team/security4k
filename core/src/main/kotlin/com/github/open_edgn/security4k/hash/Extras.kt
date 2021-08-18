@file:Suppress("unused")

package com.github.open_edgn.security4k.hash

import java.nio.charset.Charset
import kotlin.text.Charsets.UTF_8

fun String.md5Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, HashUtils.METHOD.MD5)
fun String.sha1Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, HashUtils.METHOD.SHA1)
fun String.sha224Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, HashUtils.METHOD.SHA224)
fun String.sha256Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, HashUtils.METHOD.SHA256)
fun String.sha384Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, HashUtils.METHOD.SHA384)
fun String.sha512Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, HashUtils.METHOD.SHA512)
fun String.crc32Sum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, HashUtils.METHOD.CRC32)
fun String.crc32cSum(charset: Charset = UTF_8) = HashUtils.loadTextHash(this, charset, HashUtils.METHOD.CRC32C)
