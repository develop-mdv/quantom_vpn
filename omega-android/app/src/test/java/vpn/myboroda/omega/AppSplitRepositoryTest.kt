package vpn.myboroda.omega

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AppSplitRepositoryTest {
    @Test
    fun catalogIncludesInternetPackagesWithoutLauncherActivities() {
        val apps = AppSplitRepository.buildCatalog(
            packages = listOf(
                RawInstalledPackage(
                    label = "Browser",
                    packageName = "com.browser",
                    hasInternetPermission = true,
                    hasLauncherActivity = true,
                    isSystem = false,
                ),
                RawInstalledPackage(
                    label = "Sync Engine",
                    packageName = "com.sync.engine",
                    hasInternetPermission = true,
                    hasLauncherActivity = false,
                    isSystem = true,
                ),
                RawInstalledPackage(
                    label = "Calculator",
                    packageName = "com.calc",
                    hasInternetPermission = false,
                    hasLauncherActivity = true,
                    isSystem = false,
                ),
            ),
            selectedPackages = setOf("com.sync.engine"),
            ownPackage = "vpn.myboroda.omega",
            query = "",
        )

        assertEquals(listOf("com.sync.engine", "com.browser"), apps.map { it.packageName })
        assertTrue(apps.first { it.packageName == "com.sync.engine" }.selected)
        assertTrue(apps.first { it.packageName == "com.sync.engine" }.system)
    }

    @Test
    fun ownPackageIsVisibleButNotSelectable() {
        val apps = AppSplitRepository.buildCatalog(
            packages = listOf(
                RawInstalledPackage(
                    label = "Omega VPN",
                    packageName = "vpn.myboroda.omega",
                    hasInternetPermission = true,
                    hasLauncherActivity = true,
                    isSystem = false,
                ),
            ),
            selectedPackages = setOf("vpn.myboroda.omega"),
            ownPackage = "vpn.myboroda.omega",
            query = "",
        )

        assertEquals(1, apps.size)
        assertFalse(apps.single().selectable)
        assertTrue(apps.single().selected)
    }

    @Test
    fun searchMatchesLabelAndPackageName() {
        val apps = AppSplitRepository.buildCatalog(
            packages = listOf(
                RawInstalledPackage(
                    label = "Maps",
                    packageName = "com.maps",
                    hasInternetPermission = true,
                    hasLauncherActivity = true,
                    isSystem = false,
                ),
                RawInstalledPackage(
                    label = "Updater",
                    packageName = "com.android.updater",
                    hasInternetPermission = true,
                    hasLauncherActivity = false,
                    isSystem = true,
                ),
            ),
            selectedPackages = emptySet(),
            ownPackage = "vpn.myboroda.omega",
            query = "android",
        )

        assertEquals(listOf("com.android.updater"), apps.map { it.packageName })
    }
}
