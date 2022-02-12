package org.d7z.security4k.base64

import org.d7z.security4k.api.ITextDataCovert

/**
 * Base64 工具类
 *
 * 作为使用者，你需要明白 Base64/32 并非一种加/解密算法
 *
 */
object Base64Utils {
    /**
     * 默认的 Base64 实现
     */
    val simpleBase64: ITextDataCovert = SimpleBase64Format(urlMode = false, mimeMode = false)

    /**
     * Base64 - URL and Filename safe 实现
     */
    val urlBase64: ITextDataCovert = SimpleBase64Format(urlMode = true, mimeMode = false)

    /**
     * Base64 MIME 定长
     */
    val mimeBase64: ITextDataCovert = SimpleBase64Format(urlMode = false, mimeMode = true)

    /**
     * Base64 MIME 定长 + URL and Filename safe 实现
     */
    val mimeUrlBase64: ITextDataCovert = SimpleBase64Format(urlMode = true, mimeMode = true)
}
