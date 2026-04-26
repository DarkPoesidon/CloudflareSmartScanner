package com.example.enginewrapper

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {
    private lateinit var actionButton: Button
    private lateinit var resultText: TextView
    private var running = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        actionButton = findViewById(R.id.actionButton)
        resultText = findViewById(R.id.resultText)

        actionButton.setOnClickListener {
            if (running) {
                stopEngine()
            } else {
                startEngine()
            }
        }
    }

    private fun startEngine() {
        running = true
        actionButton.text = getString(R.string.stop_button)
        resultText.text = "Starting engine..."

        val started = EngineBridge.start()
        resultText.text = if (started) {
            "Engine started. Pulling latest result..."
        } else {
            "Engine start failed. Check AAR integration and exported interface names."
        }

        if (started) {
            updateResultText()
        }
    }

    private fun stopEngine() {
        running = false
        actionButton.text = getString(R.string.start_button)
        EngineBridge.stop()
        resultText.text = "Engine stopped."
    }

    private fun updateResultText() {
        if (!running) return
        val result = EngineBridge.fetchResult()
        resultText.text = if (result.isNotBlank()) {
            result
        } else {
            "Engine is running. Results will appear here when available."
        }
    }
}
