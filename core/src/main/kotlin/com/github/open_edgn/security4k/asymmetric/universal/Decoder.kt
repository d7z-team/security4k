package com.github.open_edgn.security4k.asymmetric.universal

import java.io.InputStream
import java.io.OutputStream

/**
 * 解密数据
 */
interface Decoder {
    /**
     *
     * 解密数据
     *
     * @param cipherStream InputStream 密文
     * @param plainStream OutputStream 明文
     */
    fun decode(cipherStream: InputStream, plainStream: OutputStream)
}