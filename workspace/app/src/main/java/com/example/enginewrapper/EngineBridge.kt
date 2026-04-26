package com.example.enginewrapper

import android.util.Log

object EngineBridge {
    private const val TAG = "EngineBridge"
    private const val ENGINE_CLASS_NAME = "org.golang.engine.Engine"
    private var engineInstance: Any? = null
    private var startMethod: java.lang.reflect.Method? = null
    private var stopMethod: java.lang.reflect.Method? = null
    private var fetchResultMethod: java.lang.reflect.Method? = null

    init {
        initializeBridge()
    }

    private fun initializeBridge() {
        try {
            val engineClass = Class.forName(ENGINE_CLASS_NAME)
            startMethod = engineClass.getMethod("start")
            stopMethod = engineClass.getMethod("stop")
            fetchResultMethod = engineClass.getMethod("fetchResult")

            engineInstance = try {
                engineClass.getDeclaredConstructor().newInstance()
            } catch (e: Exception) {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to initialize Go engine bridge. Update ENGINE_CLASS_NAME and method names to match the AAR.", e)
        }
    }

    fun start(): Boolean {
        return try {
            startMethod?.invoke(engineInstance)
            true
        } catch (e: Exception) {
            Log.w(TAG, "Failed to invoke start()", e)
            false
        }
    }

    fun stop(): Boolean {
        return try {
            stopMethod?.invoke(engineInstance)
            true
        } catch (e: Exception) {
            Log.w(TAG, "Failed to invoke stop()", e)
            false
        }
    }

    fun fetchResult(): String {
        return try {
            fetchResultMethod?.invoke(engineInstance)?.toString() ?: ""
        } catch (e: Exception) {
            Log.w(TAG, "Failed to invoke fetchResult()", e)
            ""
        }
    }
}
