package com.ritam.fishnet

import android.content.pm.PackageManager
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ThreatHistoryAdapter(
    private val packageManager: PackageManager
) : ListAdapter<ScanResult, ThreatHistoryAdapter.ResultViewHolder>(Diff) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ResultViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_scan_result, parent, false)
        return ResultViewHolder(view, packageManager)
    }

    override fun onBindViewHolder(holder: ResultViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class ResultViewHolder(
        itemView: View,
        private val packageManager: PackageManager
    ) : RecyclerView.ViewHolder(itemView) {

        private val icon: ImageView = itemView.findViewById(R.id.ivAppIcon)
        private val appName: TextView = itemView.findViewById(R.id.tvAppName)
        private val preview: TextView = itemView.findViewById(R.id.tvPreview)
        private val result: TextView = itemView.findViewById(R.id.tvResult)
        private val timestamp: TextView = itemView.findViewById(R.id.tvTimestamp)

        fun bind(item: ScanResult) {
            val packageLabel = resolveAppName(item.packageName)
            appName.text = packageLabel
            preview.text = item.text.ifBlank { "No notification text available" }
            result.text = displayCategory(item)
            timestamp.text = TIME_FORMAT.format(Date(item.timestamp))
            applyResultColor(item.category)
            bindIcon(item.packageName)
        }

        private fun resolveAppName(packageName: String): String {
            return runCatching {
                packageManager.getApplicationLabel(
                    packageManager.getApplicationInfo(packageName, 0)
                ).toString()
            }.getOrElse { packageName }
        }

        private fun bindIcon(packageName: String) {
            val drawable = runCatching { packageManager.getApplicationIcon(packageName) }
                .getOrNull()
            if (drawable != null) {
                icon.setImageDrawable(drawable)
            } else {
                icon.setImageResource(android.R.drawable.sym_def_app_icon)
            }
        }

        private fun applyResultColor(category: String) {
            val colorRes = when (category) {
                ScanCategory.PHISHING.name -> R.color.phishing_red
                ScanCategory.SCAM.name -> R.color.risk_orange
                ScanCategory.USEFUL.name -> R.color.safe_green
                ScanCategory.IRRELEVANT.name -> R.color.irrelevant_gray
                else -> R.color.irrelevant_gray
            }
            result.setTextColor(ContextCompat.getColor(itemView.context, colorRes))
        }

        private fun displayCategory(item: ScanResult): String {
            if (item.category == ScanCategory.PHISHING.name || item.category == ScanCategory.SCAM.name) {
                val parsed = ScanCategory.values().firstOrNull { it.name == item.category }
                return item.subtype ?: (parsed?.displayLabel() ?: item.category)
            }
            val parsed = ScanCategory.values().firstOrNull { it.name == item.category }
            return parsed?.displayLabel() ?: item.category
        }
    }

    private object Diff : DiffUtil.ItemCallback<ScanResult>() {
        override fun areItemsTheSame(oldItem: ScanResult, newItem: ScanResult): Boolean {
            return oldItem.notificationId == newItem.notificationId
        }

        override fun areContentsTheSame(oldItem: ScanResult, newItem: ScanResult): Boolean {
            return oldItem == newItem
        }
    }

    companion object {
        private val TIME_FORMAT = SimpleDateFormat("dd MMM yyyy, HH:mm", Locale.getDefault())
    }
}
