package com.github.open_edgn.security4k.base64

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.io.ByteArrayOutputStream
import java.io.PrintWriter

internal class Base64UtilsTest {

    private val encodes = arrayListOf(
        "ZmhzZGZzZGprZmFzZGprZmhhc2RrbGZhc2tsZGZoYXNka2pmaGFza2xmaGFza2RmaGFsa2ZoYXNka2xmaGFzZGZqa2hhc2Rma2hzZGZraGFzZmtsaHNma2hma2phc2ZraGFzZGZrbGhzZGZqa2hhc2Rma2hhc2prZGZoYXNqa2hmYXNrbGpmaGFzamtsZmhhc2tsZmhhc2tsZmhhc2RrbGZoYXNkZmtoYXNrbGZoc2FkZmtoYXNsZmtoYXNsa2Zoc2FrZmhhc2tsZmZoc2Rmc2Rqa2Zhc2Rqa2ZoYXNka2xmYXNrbGRmaGFzZGtqZmhhc2tsZmhhc2tkZmhhbGtmaGFzZGtsZmhhc2RmamtoYXNkZmtoc2Rma2hhc2ZrbGhzZmtoZmtqYXNma2hhc2Rma2xoc2RmamtoYXNkZmtoYXNqa2RmaGFzamtoZmFza2xqZmhhc2prbGZoYXNrbGZoYXNrbGZoYXNka2xmaGFzZGZraGFza2xmaHNhZGZraGFzbGZraGFzbGtmaHNha2ZoYXNrbGZmaHNkZnNkamtmYXNkamtmaGFzZGtsZmFza2xkZmhhc2RramZoYXNrbGZoYXNrZGZoYWxrZmhhc2RrbGZoYXNkZmpraGFzZGZraHNkZmtoYXNma2xoc2ZraGZramFzZmtoYXNkZmtsaHNkZmpraGFzZGZraGFzamtkZmhhc2praGZhc2tsamZoYXNqa2xmaGFza2xmaGFza2xmaGFzZGtsZmhhc2Rma2hhc2tsZmhzYWRma2hhc2xma2hhc2xrZmhzYWtmaGFza2xmZmhzZGZzZGprZmFzZGprZmhhc2RrbGZhc2tsZGZoYXNka2pmaGFza2xmaGFza2RmaGFsa2ZoYXNka2xmaGFzZGZqa2hhc2Rma2hzZGZraGFzZmtsaHNma2hma2phc2ZraGFzZGZrbGhzZGZqa2hhc2Rma2hhc2prZGZoYXNqa2hmYXNrbGpmaGFzamtsZmhhc2tsZmhhc2tsZmhhc2RrbGZoYXNkZmtoYXNrbGZoc2FkZmtoYXNsZmtoYXNsa2Zoc2FrZmhhc2tsZmZoc2Rmc2Rqa2Zhc2Rqa2ZoYXNka2xmYXNrbGRmaGFzZGtqZmhhc2tsZmhhc2tkZmhhbGtmaGFzZGtsZmhhc2RmamtoYXNkZmtoc2Rma2hhc2ZrbGhzZmtoZmtqYXNma2hhc2Rma2xoc2RmamtoYXNkZmtoYXNqa2RmaGFzamtoZmFza2xqZmhhc2prbGZoYXNrbGZoYXNrbGZoYXNka2xmaGFzZGZraGFza2xmaHNhZGZraGFzbGZraGFzbGtmaHNha2ZoYXNrbGZmaHNkZnNkamtmYXNkamtmaGFzZGtsZmFza2xkZmhhc2RramZoYXNrbGZoYXNrZGZoYWxrZmhhc2RrbGZoYXNkZmpraGFzZGZraHNkZmtoYXNma2xoc2ZraGZramFzZmtoYXNkZmtsaHNkZmpraGFzZGZraGFzamtkZmhhc2praGZhc2tsamZoYXNqa2xmaGFza2xmaGFza2xmaGFzZGtsZmhhc2Rma2hhc2tsZmhzYWRma2hhc2xma2hhc2xrZmhzYWtmaGFza2xm",
        "SGVsbG9Xb3JsZA==",
        "YXNkYXNkYQ=="

    )
    private val decodes = arrayListOf(
        "fhsdfsdjkfasdjkfhasdklfaskldfhasdkjfhasklfhaskdfhalkfhasdklfhasdfjkhasdfkhsdfkhasfklhsfkhfkjasfkhasdfklhsdfjkhasdfkhasjkdfhasjkhfaskljfhasjklfhasklfhasklfhasdklfhasdfkhasklfhsadfkhaslfkhaslkfhsakfhasklffhsdfsdjkfasdjkfhasdklfaskldfhasdkjfhasklfhaskdfhalkfhasdklfhasdfjkhasdfkhsdfkhasfklhsfkhfkjasfkhasdfklhsdfjkhasdfkhasjkdfhasjkhfaskljfhasjklfhasklfhasklfhasdklfhasdfkhasklfhsadfkhaslfkhaslkfhsakfhasklffhsdfsdjkfasdjkfhasdklfaskldfhasdkjfhasklfhaskdfhalkfhasdklfhasdfjkhasdfkhsdfkhasfklhsfkhfkjasfkhasdfklhsdfjkhasdfkhasjkdfhasjkhfaskljfhasjklfhasklfhasklfhasdklfhasdfkhasklfhsadfkhaslfkhaslkfhsakfhasklffhsdfsdjkfasdjkfhasdklfaskldfhasdkjfhasklfhaskdfhalkfhasdklfhasdfjkhasdfkhsdfkhasfklhsfkhfkjasfkhasdfklhsdfjkhasdfkhasjkdfhasjkhfaskljfhasjklfhasklfhasklfhasdklfhasdfkhasklfhsadfkhaslfkhaslkfhsakfhasklffhsdfsdjkfasdjkfhasdklfaskldfhasdkjfhasklfhaskdfhalkfhasdklfhasdfjkhasdfkhsdfkhasfklhsfkhfkjasfkhasdfklhsdfjkhasdfkhasjkdfhasjkhfaskljfhasjklfhasklfhasklfhasdklfhasdfkhasklfhsadfkhaslfkhaslkfhsakfhasklffhsdfsdjkfasdjkfhasdklfaskldfhasdkjfhasklfhaskdfhalkfhasdklfhasdfjkhasdfkhsdfkhasfklhsfkhfkjasfkhasdfklhsdfjkhasdfkhasjkdfhasjkhfaskljfhasjklfhasklfhasklfhasdklfhasdfkhasklfhsadfkhaslfkhaslkfhsakfhasklf",
        "HelloWorld",
        "asdasda"
    )

    @Test
    fun encodeText() {
        for ((i, v) in encodes.withIndex()) {
            assertEquals(
                Base64Utils.encodeText(
                    decodes[i]
                ),
                v
            )
        }
    }

    @Test
    fun decodeText() {
        for ((i, v) in encodes.withIndex()) {
            assertEquals(
                Base64Utils.decodeText(
                    v
                ),
                decodes[i]
            )
        }
    }

    @Test
    fun encodeStream() {
        for ((i, v) in decodes.withIndex()) {
            val byteArrayOutputStream = ByteArrayOutputStream()
            val writer = PrintWriter(byteArrayOutputStream)
            Base64Utils.encodeStream(v.toByteArray(Charsets.UTF_8).inputStream(), writer)
            writer.flush()
            assertEquals(encodes[i], byteArrayOutputStream.toByteArray().toString(Charsets.UTF_8))
        }

    }

    @Test
    fun decodeStream() {
        for ((i, v) in encodes.withIndex()) {
            val byteArrayOutputStream = ByteArrayOutputStream()
            Base64Utils.decodeStream(v.reader(), byteArrayOutputStream)
            assertEquals(decodes[i], byteArrayOutputStream.toString(Charsets.UTF_8))
        }
    }
}