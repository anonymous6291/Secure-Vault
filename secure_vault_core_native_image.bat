@echo off
native-image --enable-sbom -march=compatibility --features=com.securevault.core.ReflectionFeature -jar .\target\secure-vault-core-1.0-SNAPSHOT.jar SecureVault
@echo on