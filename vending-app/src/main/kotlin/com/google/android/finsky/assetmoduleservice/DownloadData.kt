/*
 * SPDX-FileCopyrightText: 2023 microG Project Team
 * SPDX-License-Identifier: Apache-2.0
 */

package com.google.android.finsky.assetmoduleservice

import java.io.Serializable

data class DownloadData(
    var packageName: String = "",
    var errorCode: Int = 0,
    var sessionIds: Map<String, Int> = emptyMap(),
    var bytesDownloaded: Long = 0,
    var status: Int = 0,
    var moduleNames: Set<String> = emptySet(),
    var appVersionCode: Long = 0,
    var totalBytesToDownload: Long = 0,
    var moduleDataMap: Map<String, ModuleData> = emptyMap()
) : Serializable {

    fun getModuleData(moduleName: String): ModuleData {
        return moduleDataMap[moduleName] ?: throw IllegalArgumentException("ModuleData for moduleName '$moduleName' not found.")
    }

    fun incrementModuleBytesDownloaded(packName: String, bytes: Long) {
        getModuleData(packName).incrementBytesDownloaded(bytes)
        bytesDownloaded += bytes
    }

    fun updateDownloadStatus(packName: String, statusCode: Int) {
        getModuleData(packName).apply {
            status = statusCode
        }
    }
}

data class ModuleData(
    var packVersionCode: Long = 0,
    var moduleVersion: Long = 0,
    var errorCode: Int = 0,
    var status: Int = 0,
    var bytesDownloaded: Long = 0,
    var totalBytesToDownload: Long = 0,
    var chunks: List<ChunkData> = emptyList(),
    var sliceIds: ArrayList<String>? = null
) : Serializable {
    fun incrementBytesDownloaded(bytes: Long) {
        bytesDownloaded += bytes
    }
}

data class ChunkData(
    val sessionId: Int,
    val moduleName: String,
    val sliceId: String?,
    val chunkSourceUri: String?,
    val chunkBytesToDownload: Long,
    val chunkIndex: Int,
    val sliceUncompressedSize: Long,
    val sliceUncompressedHashSha256: String?,
    val numberOfChunksInSlice: Int
)