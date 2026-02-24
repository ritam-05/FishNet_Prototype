package com.ritam.fishnet

import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.appbar.MaterialToolbar
import kotlinx.coroutines.launch

class HistoryActivity : AppCompatActivity() {

    private lateinit var viewModel: HistoryViewModel
    private lateinit var adapter: ThreatHistoryAdapter
    private lateinit var rvHistory: RecyclerView
    private lateinit var tvEmpty: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_history)

        viewModel = ViewModelProvider(this)[HistoryViewModel::class.java]
        adapter = ThreatHistoryAdapter(packageManager)
        rvHistory = findViewById(R.id.rvHistory)
        tvEmpty = findViewById(R.id.tvHistoryEmpty)

        findViewById<MaterialToolbar>(R.id.toolbarHistory).setNavigationOnClickListener {
            finish()
        }
        setupRecycler()
        observeResults()
    }

    private fun setupRecycler() {
        rvHistory.layoutManager = LinearLayoutManager(this)
        rvHistory.adapter = adapter
        rvHistory.itemAnimator = androidx.recyclerview.widget.DefaultItemAnimator()
    }

    private fun observeResults() {
        lifecycleScope.launch {
            viewModel.results.collect { results ->
                adapter.submitList(results)
                tvEmpty.visibility = if (results.isEmpty()) View.VISIBLE else View.GONE
            }
        }
    }

}
