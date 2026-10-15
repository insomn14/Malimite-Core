package io.malimite.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** iOS/macOS framework and third-party SDK prefixes whose functions are skipped during decompilation. */
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

    /**
     * Well-known third-party iOS SDK namespace/module prefixes, matched the same way as
     * {@link #DEFAULT_LIBRARIES} ({@code namespace.startsWith(prefix)} in DumpClassData) —
     * skipped before Ghidra decompiles their functions, same as a system framework.
     *
     * <p>Not exhaustive: this only covers popular CocoaPods/SPM dependencies whose module
     * name is distinctive enough that a startsWith match is very unlikely to also catch a
     * first-party class (e.g. {@code "Branch"} or {@code "Segment"} are deliberately left
     * out — too generic, likely to collide with an app's own class/feature names). An app
     * with an unusual or custom-built SDK will still have it fully decompiled.
     */
    private static final List<String> THIRD_PARTY_SDKS = Arrays.asList(
        // Firebase
        "Firebase", "FirebaseCore", "FirebaseCoreInternal", "FirebaseAnalytics",
        "FirebaseAuth", "FirebaseFirestore", "FirebaseFirestoreInternal",
        "FirebaseMessaging", "FirebaseCrashlytics", "FirebaseInstallations",
        "FirebaseRemoteConfig", "FirebaseDatabase", "FirebaseStorage",
        "FirebaseDynamicLinks", "FirebaseABTesting", "FirebasePerformance",
        "FirebaseSessions", "FirebaseSharedSwift",
        // Google / gRPC transitive deps Firebase pulls in
        "GoogleUtilities", "GoogleDataTransport", "GoogleSignIn", "GoogleMaps",
        "GoogleMapsBase", "GoogleMapsCore", "GoogleMapsM4B", "GoogleAppMeasurement",
        "GoogleAppMeasurementIdentitySupport", "GTMSessionFetcher", "GTMAppAuth",
        "AppAuth", "PromisesObjC", "PromisesSwift", "nanopb", "leveldb", "grpc",
        "grpcpp", "openssl_grpc", "abseil", "BoringSSL",
        // Facebook
        "FBSDKCoreKit", "FBSDKLoginKit", "FBSDKShareKit", "FBSDKGamingServicesKit",
        "FBAEMKit", "FBLPromises",
        // Networking / reactive / UI / utility
        "Alamofire", "RxSwift", "RxCocoa", "RxRelay", "SDWebImage",
        "SDWebImageSwiftUI", "Kingfisher", "SnapKit", "SwiftyJSON", "Moya",
        "ObjectMapper", "Starscream", "SwiftProtobuf", "Lottie", "KeychainAccess",
        // Storage
        "Realm", "RealmSwift", "RealmDatabase",
        // Analytics / crash / monitoring
        "Mixpanel", "Sentry", "Bugsnag", "Crashlytics", "AppsFlyerLib",
        "AdjustSdk",
        // Logging
        "CocoaLumberjack", "CocoaLumberjackSwift"
    );

    public static List<String> getDefaultLibraries() {
        return DEFAULT_LIBRARIES;
    }

    public static List<String> getThirdPartySdks() {
        return THIRD_PARTY_SDKS;
    }

    public static List<String> getActiveLibraries(CoreConfig config) {
        Set<String> active = new HashSet<>(DEFAULT_LIBRARIES);
        active.addAll(THIRD_PARTY_SDKS);
        active.removeAll(config.getRemovedLibraries());
        active.addAll(config.getAddedLibraries());
        List<String> sorted = new ArrayList<>(active);
        Collections.sort(sorted);
        return sorted;
    }
}
