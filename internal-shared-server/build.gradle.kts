plugins {
    application
}

dependencies {
    implementation(project(":core"))
    implementation(project(":security"))
    implementation(project(":annotations"))
}

application {
    mainClass.set("space.qu4nt.entanglementlib.iss.ISSRunner")
    applicationDefaultJvmArgs = listOf(
        "--enable-native-access=ALL-UNNAMED",
        // logback 의 내부 status 메시지를 억제한다 (클래스패스에 logback.xml 이 둘이라 발생하는 잡음 차단)
        "-Dlogback.statusListenerClass=ch.qos.logback.core.status.NopStatusListener"
    )
}
