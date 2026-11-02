dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    implementation("com.google.crypto.tink:tink:1.13.0")
    implementation(group = "io.jsonwebtoken", name = "jjwt-api", version = "0.12.5")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    // implementation("org.bouncycastle:bcpg-jdk18on:1.78.1")   (commented out)
}
