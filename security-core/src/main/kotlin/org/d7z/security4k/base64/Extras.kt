package org.d7z.security4k.base64

import java.nio.charset.Charset

@Suppress("unused")
fun String.base64Encode(charset: Charset = Charsets.UTF_8): String = Base64Utils.encodeText(this, charset)

@Suppress("unused")
fun String.base64Decode(charset: Charset = Charsets.UTF_8): String = Base64Utils.decodeText(this, charset)
