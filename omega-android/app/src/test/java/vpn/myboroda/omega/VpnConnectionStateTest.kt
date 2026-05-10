package vpn.myboroda.omega

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnConnectionStateTest {
    @Test
    fun parsesStoredStateWithDisconnectedFallback() {
        assertEquals(VpnConnectionState.CONNECTING, VpnConnectionState.fromStored("CONNECTING"))
        assertEquals(VpnConnectionState.CONNECTED, VpnConnectionState.fromStored("CONNECTED"))
        assertEquals(VpnConnectionState.DISCONNECTED, VpnConnectionState.fromStored("broken"))
        assertEquals(VpnConnectionState.DISCONNECTED, VpnConnectionState.fromStored(null))
    }
}
