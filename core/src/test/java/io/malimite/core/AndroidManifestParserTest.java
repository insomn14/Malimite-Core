package io.malimite.core;

import net.dongliu.apk.parser.bean.ApkMeta;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AndroidManifestParserTest {

    @Test
    void parsesExportedComponentsFlagsAndDeepLinks() throws Exception {
        String xml = """
                <?xml version="1.0" encoding="utf-8"?>
                <manifest package="com.example.app">
                  <uses-permission android:name="android.permission.INTERNET"/>
                  <uses-permission android:name="android.permission.READ_SMS"/>
                  <application android:debuggable="true"
                               android:allowBackup="true"
                               android:usesCleartextTraffic="true"
                               android:networkSecurityConfig="@xml/network_security_config">
                    <activity android:name=".MainActivity" android:exported="true">
                      <intent-filter>
                        <action android:name="android.intent.action.VIEW"/>
                        <data android:scheme="myapp" android:host="open" android:pathPrefix="/x"/>
                      </intent-filter>
                    </activity>
                    <service android:name=".SyncService" android:exported="false"/>
                    <receiver android:name=".BootReceiver" android:exported="true"
                              android:permission="android.permission.RECEIVE_BOOT_COMPLETED"/>
                  </application>
                </manifest>
                """;
        ApkMeta meta = ApkMeta.newBuilder()
                .setPackageName("com.example.app")
                .setMinSdkVersion("24")
                .setTargetSdkVersion("34")
                .addUsesPermission("android.permission.INTERNET")
                .addUsesPermission("android.permission.READ_SMS")
                .build();

        AndroidManifestParser.ManifestInfo info =
                AndroidManifestParser.fromMetaAndXml(meta, xml);

        assertEquals("com.example.app", info.packageName());
        assertEquals(24, info.minSdk());
        assertEquals(34, info.targetSdk());
        assertTrue(info.debuggable());
        assertTrue(info.allowBackup());
        assertTrue(info.usesCleartextTraffic());
        assertEquals("@xml/network_security_config", info.networkSecurityConfig());
        assertTrue(info.permissions().stream().anyMatch(p -> p.contains("READ_SMS")));
        assertEquals(3, info.components().size());
        assertFalse(info.deepLinks().isEmpty());
        assertEquals("myapp", info.deepLinks().get(0).scheme());

        var main = info.components().stream()
                .filter(c -> c.name().contains("MainActivity")).findFirst().orElseThrow();
        assertTrue(main.exported());
    }
}
