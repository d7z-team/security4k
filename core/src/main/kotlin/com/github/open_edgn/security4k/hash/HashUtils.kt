package com.github.open_edgn.security4k.hash

import java.io.InputStream
import java.nio.charset.Charset

object HashUtils {
    /**
     *
     * @property hashCalculate BaseHashCalculate
     * @constructor
     */
    enum class METHOD(val hashCalculate: BaseHashCalculate) {
        MD5(SimpleHashCalculate("md5")),
        SHA1(SimpleHashCalculate("sha1")),
        SHA224(SimpleHashCalculate("sha-224")),
        SHA256(SimpleHashCalculate("sha-256")),
        SHA384(SimpleHashCalculate("sha-384")),
        SHA512(SimpleHashCalculate("sha-512")),
        CRC32(CRC32HashCalculate()),
        CRC32C(CRC32CHashCalculate())
    }

    /**
     * 计算流的哈希值
     *
     * @param input InputStream 流
     * @param method METHOD 哈希值算法
     * @return String 哈希值
     */
    fun loadHash(input: InputStream, method: METHOD): String {
        return method.hashCalculate.calculate(input)
    }

    /**
     * 计算文本哈希值
     * @param data String 文本
     * @param charset Charset 编码方式
     * @param method METHOD 哈希值算法
     * @return String 哈希值
     */
    fun loadTextHash(data: String, charset: Charset, method: METHOD): String {
        return loadHash(data.byteInputStream(charset), method)
    }


    /**
     * 异步计算哈希值
     *
     * @param input InputStream 被计算的流
     * @param method 哈希值计算算法
     * @param hook Function1<String, Unit> 回调接口
     */
    fun asyncLoadHash(
        input: InputStream,
        method: METHOD,
        hook: (String) -> Unit,
        hookRuntime: (Runnable) -> Unit = { Thread(it).run() }
    ) {
        val runnable = Runnable {
            val calculate = loadHash(input, method)
            hook(calculate)
        }
        hookRuntime(runnable)
    }
}