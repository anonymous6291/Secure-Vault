package com.securevault.core;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

public class Main {
    private static final String DEPENDENT_MODE_ARGUMENT = "-d";

    static void main(String[] args) {
        boolean dependentMode = false;
        if (args != null) {
            for (String s : args) {
                if (s != null && s.equals(DEPENDENT_MODE_ARGUMENT)) {
                    dependentMode = true;
                    break;
                }
            }
        }
        if (dependentMode) {
            try {
                ObjectMapper objectMapper = new ObjectMapper();
                objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                DependentMode.start(objectMapper.readValue(IO.readln(), IPCSpec.class));
            } catch (Exception e) {
                IO.println("ERROR;" + e.getMessage());
            }
        } else {
            IndependentMode.start(args);
        }
    }
}
