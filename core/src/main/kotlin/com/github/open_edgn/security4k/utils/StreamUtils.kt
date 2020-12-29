package com.github.open_edgn.security4k.utils

import java.io.InputStream

/**
 * 利用缓冲区循环读取流中数据
 *
 * @receiver InputStream 流
 * @param bufferSize Int 缓冲区大小
 * @param func Function2<ByteArray, Int, Unit> 代码执行函数
 */
internal inline fun <T : InputStream> T.foreach(bufferSize: Int = 4096, func: T.(ByteArray, Int) -> Unit) {
    val b = ByteArray(bufferSize)
    while (true) {
        val len = read(b, 0, bufferSize)
        if (len == -1) {
            break
        }
        func(b, len)
    }
    close()
}
