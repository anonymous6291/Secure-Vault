package com.securevault.core.keyhandlers;

public record WebsiteIdPair(String websiteName, String id) implements Comparable<WebsiteIdPair> {
    public static String convertToJSON(WebsiteIdPair websiteIdPair) {
        return "{\"websiteName\":\"" + websiteIdPair.websiteName() + "\",\"id\":\"" + websiteIdPair.id() + "\"}";
    }

    @Override
    public int compareTo(WebsiteIdPair websiteIdPair) {
        int v = websiteName.compareTo(websiteIdPair.websiteName);
        return v != 0 ? v : id.compareTo(websiteIdPair.id);
    }
}
