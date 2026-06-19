package com.securevault.core;

import com.securevault.core.configurations.ConfigurationManager;
import com.securevault.core.keyhandlers.PairValue;
import com.securevault.core.keyhandlers.WebsiteIdPair;
import org.graalvm.nativeimage.hosted.Feature;
import org.graalvm.nativeimage.hosted.RuntimeReflection;

public class ReflectionFeature implements Feature {
    @Override
    public void beforeAnalysis(BeforeAnalysisAccess analysisAccess) {
        registerClass(WebsiteIdPair.class);
        registerClass(PairValue.class);
        registerClass(ConfigurationManager.Configuration.class);
        registerClass(CommandType.class);
        registerClass(DependentMode.Command.class);
        registerClass(OutputType.class);
        registerClass(DependentMode.Output.class);
        registerClass(IPCSpec.class);
    }

    private void registerClass(Class<?> clazz) {
        RuntimeReflection.register(clazz);
        RuntimeReflection.register(clazz.getDeclaredConstructors());
        RuntimeReflection.register(clazz.getDeclaredMethods());
        RuntimeReflection.register(clazz.getDeclaredFields());
    }
}
