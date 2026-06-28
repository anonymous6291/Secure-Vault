#!/bin/sh
native-image --enable-sbom -march=compatibility --features=com.securevault.core.ReflectionFeature -jar ./target/secure-vault-core-2.0.0.jar SecureVault