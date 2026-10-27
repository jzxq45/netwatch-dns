package com.example.netwatch

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.net.HttpURLConnection
import java.net.URL

class SettingsActivity : AppCompatActivity() {

    private lateinit var prefs: android.content.SharedPreferences
    private lateinit var edtServer: EditText
    private lateinit var edtToken: EditText
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)
        prefs = getSharedPreferences("netwatch", MODE_PRIVATE)
        edtServer = findViewById(R.id.edtServer)
        edtToken = findViewById(R.id.edtToken)
        status = findViewById(R.id.txtStatus)

        edtServer.setText(prefs.getString("server_url", MainActivity.DEFAULT_URL))
        edtToken.setText(prefs.getString("api_token", ""))

        findViewById<Button>(R.id.btnTest).setOnClickListener { test() }
        findViewById<Button>(R.id.btnSave).setOnClickListener { save() }
        findViewById<Button>(R.id.btnReset).setOnClickListener { reset() }
    }

    private fun base(): String =
        edtServer.text.toString().trim().trimEnd('/')

    private fun test() {
        status.text = getString(R.string.status_testing)
        val target = base() + "/healthz"
        val token = edtToken.text.toString().trim()
        val btnTest = findViewById<Button>(R.id.btnTest)
        btnTest.isEnabled = false
        Thread {
            val msg: String = try {
                val conn = URL(target).openConnection() as HttpURLConnection
                conn.connectTimeout = 3000
                conn.readTimeout = 3000
                if (token.isNotBlank()) conn.setRequestProperty("X-Auth-Token", token)
                conn.requestMethod = "GET"
                val code = conn.responseCode
                conn.disconnect()
                if (code == 200) getString(R.string.status_ok)
                else getString(R.string.status_http, code)
            } catch (e: Exception) {
                getString(R.string.status_fail, e.message ?: "unknown")
            }
            runOnUiThread {
                status.text = msg
                btnTest.isEnabled = true
            }
        }.start()
    }

    private fun save() {
        val u = base()
        if (!(u.startsWith("http://") || u.startsWith("https://"))) {
            status.text = getString(R.string.status_fail, "адрес должен начинаться с http:// или https://")
            return
        }
        prefs.edit()
            .putString("server_url", u)
            .putString("api_token", edtToken.text.toString().trim())
            .putBoolean("reload_needed", true)
            .apply()
        finish()
    }

    private fun reset() {
        prefs.edit()
            .putString("server_url", MainActivity.DEFAULT_URL)
            .putString("api_token", "")
            .putBoolean("reload_needed", true)
            .apply()
        edtServer.setText(MainActivity.DEFAULT_URL)
        edtToken.setText("")
        status.text = getString(R.string.status_ok)
    }
}