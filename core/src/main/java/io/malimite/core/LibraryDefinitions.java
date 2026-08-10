package io.malimite.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** iOS/macOS framework prefixes whose functions are skipped during decompilation. */
public final class LibraryDefinitions {

    private LibraryDefinitions() {}

    private static final List<String> DEFAULT_LIBRARIES = Arrays.asList(
        "ARKit", "AppTrackingTransparency", "AuthenticationServices",
        "AVFoundation", "BackgroundTasks", "CallKit", "CFNetwork",
        "CloudKit", "Combine", "Contacts", "CoreBluetooth", "CoreData",
        "CoreFoundation", "CoreGraphics", "CoreImage", "CoreLocation",
        "CoreML", "CoreMotion", "CoreText", "FileProvider", "Foundation",
        "GameKit", "HealthKit", "HomeKit", "Intents", "MapKit",
        "MediaPlayer", "MessageUI", "Metal", "NaturalLanguage",
        "NetworkExtension", "PassKit", "Photos", "QuartzCore",
        "SceneKit", "Security", "SpriteKit", "StoreKit",
        "SwiftStandardLibrary", "SwiftUI", "SystemConfiguration",
        "TextKit", "UIKit", "UserNotifications", "Vision", "WebKit"
    );

    public static List<String> getDefaultLibraries() {
        return DEFAULT_LIBRARIES;
    }

    public static List<String> getActiveLibraries(CoreConfig config) {
        Set<String> active = new HashSet<>(DEFAULT_LIBRARIES);
        active.removeAll(config.getRemovedLibraries());
        active.addAll(config.getAddedLibraries());
        List<String> sorted = new ArrayList<>(active);
        Collections.sort(sorted);
        return sorted;
    }
}
