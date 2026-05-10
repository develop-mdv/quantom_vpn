package vpn.myboroda.omega

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build

data class InstalledApp(
    val label: String,
    val packageName: String,
    val selected: Boolean,
    val selectable: Boolean,
    val system: Boolean,
    val launchable: Boolean,
)

data class RawInstalledPackage(
    val label: String,
    val packageName: String,
    val hasInternetPermission: Boolean,
    val hasLauncherActivity: Boolean,
    val isSystem: Boolean,
)

class AppSplitRepository(private val context: Context) {
    fun loadInternetApps(selectedPackages: Set<String>, query: String = ""): List<InstalledApp> {
        val pm = context.packageManager
        val launchablePackages = loadLaunchablePackages(pm)
        val packages = installedPackages(pm).mapNotNull { info ->
            val appInfo = info.applicationInfo ?: return@mapNotNull null
            RawInstalledPackage(
                label = appInfo.loadLabel(pm).toString().trim().ifEmpty { info.packageName },
                packageName = info.packageName,
                hasInternetPermission = info.requestedPermissions?.contains(android.Manifest.permission.INTERNET) == true,
                hasLauncherActivity = launchablePackages.contains(info.packageName),
                isSystem = appInfo.isSystemApp(),
            )
        }

        return buildCatalog(
            packages = packages,
            selectedPackages = selectedPackages,
            ownPackage = context.packageName,
            query = query,
        )
    }

    private fun loadLaunchablePackages(pm: PackageManager): Set<String> {
        val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        return pm.queryIntentActivities(launcherIntent, PackageManager.MATCH_DEFAULT_ONLY)
            .mapNotNullTo(mutableSetOf()) { it.activityInfo?.packageName }
    }

    private fun installedPackages(pm: PackageManager): List<PackageInfo> {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(
                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong()),
            )
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(PackageManager.GET_PERMISSIONS)
        }
    }

    private fun ApplicationInfo.isSystemApp(): Boolean {
        return flags and ApplicationInfo.FLAG_SYSTEM != 0 ||
            flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP != 0
    }

    companion object {
        fun buildCatalog(
            packages: List<RawInstalledPackage>,
            selectedPackages: Set<String>,
            ownPackage: String,
            query: String,
        ): List<InstalledApp> {
            val normalizedQuery = query.trim().lowercase()
            return packages
            .asSequence()
                .filter { it.hasInternetPermission }
                .distinctBy { it.packageName }
                .filter {
                    normalizedQuery.isEmpty() ||
                        it.label.lowercase().contains(normalizedQuery) ||
                        it.packageName.lowercase().contains(normalizedQuery)
                }
                .map { app ->
                InstalledApp(
                        label = app.label.trim().ifEmpty { app.packageName },
                        packageName = app.packageName,
                        selected = selectedPackages.contains(app.packageName),
                        selectable = app.packageName != ownPackage,
                        system = app.isSystem,
                        launchable = app.hasLauncherActivity,
                )
            }
                .sortedWith(
                    compareByDescending<InstalledApp> { it.selected && it.selectable }
                        .thenBy { !it.selectable }
                        .thenBy { it.label.lowercase() }
                        .thenBy { it.packageName },
                )
                .toList()
        }
    }
}
