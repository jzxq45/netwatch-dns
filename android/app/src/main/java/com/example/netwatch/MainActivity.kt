package com.example.netwatch

import android.annotation.SuppressLint
import android.content.Intent
import android.content.SharedPreferences
import android.os.Bundle
import android.util.Patterns
import android.view.KeyEvent
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.Toolbar
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout
import java.net.URLEncoder

class MainActivity : AppCompatActivity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var webView: WebView
    private lateinit var swipe: SwipeRefreshLayout
    private lateinit var errorView: LinearLayout
    private lateinit var errorText: TextView
    private lateinit var progress: View

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = getSharedPreferences("netwatch", MODE_PRIVATE)
        if (prefs.getBoolean("first_run", true)) showFirstRunDialog()
        setContentView(R.layout.activity_main)

        setSupportActionBar(findViewById<Toolbar>(R.id.toolbar))
        webView = findViewById(R.id.webView)
        swipe = findViewById(R.id.swipe)
        errorView = findViewById(R.id.errorView)
        errorText = findViewById(R.id.errorText)
        progress = findViewById(R.id.progress)

        findViewById<Button>(R.id.btnRetry).setOnClickListener { load() }
        findViewById<Button>(R.id.btnErrorSettings).setOnClickListener { openSettings() }
        setupWebView()
        load()
    }

    private fun url(): String {
        val base = prefs.getString("server_url", null) ?: DEFAULT_URL
        val token = prefs.getString("api_token", "") ?: ""
        if (token.isBlank()) return base
        val sep = if (base.contains("?")) "&" else "?"
        return base + sep + "token=" + URLEncoder.encode(token, "UTF-8")
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView() {
        val s = webView.settings
        s.javaScriptEnabled = true
        s.domStorageEnabled = true
        s.mediaPlaybackRequiresUserGesture = false
        s.cacheMode = WebSettings.LOAD_DEFAULT
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                // Всё остаётся внутри приложения: внешний браузер не вызываем.
                val scheme = request.url.scheme ?: ""
                return scheme != "http" && scheme != "https"
            }

            override fun onPageFinished(view: WebView, url: String) {
                progress.visibility = View.GONE
                val token = prefs.getString("api_token", "") ?: ""
                if (token.isNotBlank()) {
                    val safe = token.replace("'", "")
                    view.evaluateJavascript(
                        "localStorage.setItem('auth_token', '$safe');", null
                    )
                }
            }

            override fun onReceivedError(
                view: WebView, request: WebResourceRequest, error: WebResourceError
            ) {
                if (request.isForMainFrame) showError()
            }
        }
        swipe.setOnRefreshListener { webView.reload() }
        swipe.isRefreshing = false
        swipe.setOnChildScrollUpCallback { _, _ -> webView.scrollY > 0 }
    }

    private fun load() {
        errorView.visibility = View.GONE
        webView.visibility = View.VISIBLE
        progress.visibility = View.VISIBLE
        swipe.isRefreshing = false
        webView.loadUrl(url())
    }

    private fun showError() {
        progress.visibility = View.GONE
        swipe.isRefreshing = false
        webView.visibility = View.GONE
        errorView.visibility = View.VISIBLE
        errorText.text = getString(R.string.error_no_connection, url())
    }

    private fun showFirstRunDialog() {
        val input = EditText(this).apply {
            setText(prefs.getString("server_url", null) ?: DEFAULT_URL)
            hint = DEFAULT_URL
            setSingleLine(true)
            setSelection(text.length)
        }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 16, 48, 0)
            addView(
                input,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                )
            )
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.app_name)
            .setMessage(getString(R.string.first_run_text, DEFAULT_URL))
            .setView(container)
            .setPositiveButton(R.string.yes) { _, _ ->
                val serverUrl = normalizeServerUrl(input.text.toString())
                prefs.edit()
                    .putString("server_url", serverUrl)
                    .putBoolean("first_run", false)
                    .apply()
                load()
            }
            .setNegativeButton(R.string.no) { _, _ -> finish() }
            .setCancelable(false)
            .show()
    }

    private fun normalizeServerUrl(raw: String): String {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return DEFAULT_URL
        val withScheme = if (trimmed.contains("://")) trimmed else "http://$trimmed"
        return if (isValidServerUrl(withScheme)) withScheme else DEFAULT_URL
    }

    private fun isValidServerUrl(value: String): Boolean =
        (value.startsWith("http://") || value.startsWith("https://")) &&
            Patterns.WEB_URL.matcher(value).matches()

    private fun openSettings() {
        startActivity(Intent(this, SettingsActivity::class.java))
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent?): Boolean {
        if (keyCode == KeyEvent.KEYCODE_BACK &&
            webView.visibility == View.VISIBLE && webView.canGoBack()
        ) {
            webView.goBack()
            return true
        }
        return super.onKeyDown(keyCode, event)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.menu_main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean = when (item.itemId) {
        R.id.action_settings -> { openSettings(); true }
        else -> super.onOptionsItemSelected(item)
    }

    override fun onResume() {
        super.onResume()
        if (prefs.getBoolean("reload_needed", false)) {
            prefs.edit().putBoolean("reload_needed", false).apply()
            load()
        }
    }

    companion object { const val DEFAULT_URL = "http://192.168.0.150:8080" }
}