package com.autorize.persistence;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.persistence.PersistedList;
import burp.api.montoya.persistence.PersistedObject;
import com.autorize.model.AutorizeConfigBundle;
import com.autorize.model.EnforcementDetector;
import com.autorize.model.InterceptionFilter;
import com.autorize.model.LogEntry;
import com.autorize.model.UserProfile;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

public class PersistenceManager {

    private static final String KEY_CONFIG_PREFIX = "autorize_v2_";
    private static final String KEY_USERS = KEY_CONFIG_PREFIX + "users_json";
    private static final String KEY_FILTERS = KEY_CONFIG_PREFIX + "filters_json";
    private static final String KEY_UNAUTH_DETECTORS = KEY_CONFIG_PREFIX + "unauth_detectors_json";
    private static final String KEY_LOGS = KEY_CONFIG_PREFIX + "logs_metadata_json";
    private static final String KEY_AUTO_INCREMENT = KEY_CONFIG_PREFIX + "req_counter";
    private static final String KEY_INTERCEPT_ENABLED = KEY_CONFIG_PREFIX + "intercept_enabled";
    private static final String KEY_CHECK_UNAUTH = KEY_CONFIG_PREFIX + "check_unauth";
    private static final String KEY_SAFE_METHODS_ONLY = KEY_CONFIG_PREFIX + "safe_methods_only";
    private static final String KEY_PREVENT_304 = KEY_CONFIG_PREFIX + "prevent_304";
    private static final String KEY_IGNORE_304 = KEY_CONFIG_PREFIX + "ignore_304";
    private static final String KEY_INTERCEPT_PROXY = KEY_CONFIG_PREFIX + "intercept_proxy";
    private static final String KEY_INTERCEPT_REPEATER = KEY_CONFIG_PREFIX + "intercept_repeater";
    private static final String KEY_IGNORE_EXTENSIONS = KEY_CONFIG_PREFIX + "ignore_extensions";

    private final MontoyaApi api;
    private final ObjectMapper objectMapper;
    private final PersistedObject extensionData;

    // Persisted disk-backed traffic lists managed by Burp
    private PersistedList<HttpRequestResponse> originalTrafficList;
    private PersistedList<HttpRequestResponse> unauthTrafficList;
    private final Map<String, PersistedList<HttpRequestResponse>> userTrafficLists = new ConcurrentHashMap<>();

    // In-memory runtime state synced with PersistedObject
    private final List<UserProfile> userProfiles = new CopyOnWriteArrayList<>();
    private final List<InterceptionFilter> interceptionFilters = new CopyOnWriteArrayList<>();
    private final List<EnforcementDetector> unauthDetectors = new CopyOnWriteArrayList<>();
    private final List<LogEntry> logEntries = new CopyOnWriteArrayList<>();
    private final AtomicInteger requestCounter = new AtomicInteger(1);

    private boolean interceptEnabled = false;
    private boolean checkUnauthenticated = true;
    private boolean safeMethodsOnly = true;
    private boolean prevent304 = false;
    private boolean ignore304 = true;
    private boolean interceptProxy = true;
    private boolean interceptRepeater = true;
    private boolean ignoreExtensions = true;

    public PersistenceManager(MontoyaApi api) {
        this.api = api;
        this.objectMapper = new ObjectMapper();
        this.extensionData = api.persistence().extensionData();
        initTrafficStores();
    }

    private void initTrafficStores() {
        try {
            originalTrafficList = extensionData.getHttpRequestResponseList("autorize_orig_traffic");
            if (originalTrafficList == null) {
                originalTrafficList = PersistedList.persistedHttpRequestResponseList();
                extensionData.setHttpRequestResponseList("autorize_orig_traffic", originalTrafficList);
            }

            unauthTrafficList = extensionData.getHttpRequestResponseList("autorize_unauth_traffic");
            if (unauthTrafficList == null) {
                unauthTrafficList = PersistedList.persistedHttpRequestResponseList();
                extensionData.setHttpRequestResponseList("autorize_unauth_traffic", unauthTrafficList);
            }
        } catch (Exception e) {
            api.logging().logToError("Error initializing persisted traffic stores: " + e.getMessage());
            originalTrafficList = PersistedList.persistedHttpRequestResponseList();
            unauthTrafficList = PersistedList.persistedHttpRequestResponseList();
        }
    }

    public synchronized PersistedList<HttpRequestResponse> getUserTrafficStore(String userId) {
        return userTrafficLists.computeIfAbsent(userId, id -> {
            String listKey = "autorize_user_traffic_" + id;
            try {
                PersistedList<HttpRequestResponse> list = extensionData.getHttpRequestResponseList(listKey);
                if (list == null) {
                    list = PersistedList.persistedHttpRequestResponseList();
                    extensionData.setHttpRequestResponseList(listKey, list);
                }
                return list;
            } catch (Exception e) {
                return PersistedList.persistedHttpRequestResponseList();
            }
        });
    }

    public void hydrateFromProject() {
        try {
            interceptEnabled = getBoolean(KEY_INTERCEPT_ENABLED, false);
            checkUnauthenticated = getBoolean(KEY_CHECK_UNAUTH, true);
            safeMethodsOnly = getBoolean(KEY_SAFE_METHODS_ONLY, true);
            prevent304 = getBoolean(KEY_PREVENT_304, false);
            ignore304 = getBoolean(KEY_IGNORE_304, true);
            interceptProxy = getBoolean(KEY_INTERCEPT_PROXY, true);
            interceptRepeater = getBoolean(KEY_INTERCEPT_REPEATER, true);
            ignoreExtensions = getBoolean(KEY_IGNORE_EXTENSIONS, true);

            Integer counter = extensionData.getInteger(KEY_AUTO_INCREMENT);
            if (counter != null) {
                requestCounter.set(counter);
            }

            // Hydrate Users
            String usersJson = extensionData.getString(KEY_USERS);
            if (usersJson != null && !usersJson.isBlank()) {
                List<UserProfile> loaded = objectMapper.readValue(usersJson, new TypeReference<List<UserProfile>>() {});
                userProfiles.clear();
                userProfiles.addAll(loaded);
                for (UserProfile u : loaded) {
                    getUserTrafficStore(u.getId());
                }
            } else {
                // Default User 1
                UserProfile defaultUser = new UserProfile("user_1", "User 1 (Low Priv)");
                userProfiles.add(defaultUser);
                getUserTrafficStore("user_1");
            }

            // Hydrate Interception Filters
            String filtersJson = extensionData.getString(KEY_FILTERS);
            if (filtersJson != null && !filtersJson.isBlank()) {
                List<InterceptionFilter> loaded = objectMapper.readValue(filtersJson, new TypeReference<List<InterceptionFilter>>() {});
                interceptionFilters.clear();
                interceptionFilters.addAll(loaded);
            } else {
                initDefaultFilters();
            }

            // Hydrate Unauth Detectors
            String detectorsJson = extensionData.getString(KEY_UNAUTH_DETECTORS);
            if (detectorsJson != null && !detectorsJson.isBlank()) {
                List<EnforcementDetector> loaded = objectMapper.readValue(detectorsJson, new TypeReference<List<EnforcementDetector>>() {});
                unauthDetectors.clear();
                unauthDetectors.addAll(loaded);
            }
            if (unauthDetectors.isEmpty()) {
                initDefaultUnauthDetectors();
            }

            for (UserProfile u : userProfiles) {
                if (u.getEnforcementDetectors().isEmpty()) {
                    initDefaultUserDetectors(u);
                }
            }

            // Hydrate Log Entries
            String logsJson = extensionData.getString(KEY_LOGS);
            if (logsJson != null && !logsJson.isBlank()) {
                List<LogEntry> loaded = objectMapper.readValue(logsJson, new TypeReference<List<LogEntry>>() {});
                logEntries.clear();
                logEntries.addAll(loaded);
            }

            api.logging().logToOutput("Autorize Next-Gen state loaded from project: " + logEntries.size() + " logs, " + userProfiles.size() + " users.");
        } catch (Exception e) {
            api.logging().logToError("Failed to hydrate Autorize state from project file: " + e.getMessage());
            initDefaultFilters();
            if (unauthDetectors.isEmpty()) {
                initDefaultUnauthDetectors();
            }
        }
    }

    public void initDefaultFilters() {
        interceptionFilters.clear();
        interceptionFilters.add(new InterceptionFilter(InterceptionFilter.FilterType.URL_NOT_CONTAINS_REGEX,
                "(\\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ico|map)|favicon\\.ico)(\\?.*)?$"));
        interceptionFilters.add(new InterceptionFilter(InterceptionFilter.FilterType.IGNORE_OPTIONS, ""));
    }

    public void initDefaultUnauthDetectors() {
        unauthDetectors.clear();
        unauthDetectors.add(new EnforcementDetector(EnforcementDetector.DetectorType.STATUS_CODE_EQUALS, "401"));
        unauthDetectors.add(new EnforcementDetector(EnforcementDetector.DetectorType.STATUS_CODE_EQUALS, "403"));
        unauthDetectors.add(new EnforcementDetector(EnforcementDetector.DetectorType.BODY_CONTAIN, "unauthorized"));
        unauthDetectors.add(new EnforcementDetector(EnforcementDetector.DetectorType.BODY_CONTAIN, "access denied"));
        unauthDetectors.add(new EnforcementDetector(EnforcementDetector.DetectorType.HEADERS_CONTAIN, "Location: /login"));
    }

    public void initDefaultUserDetectors(UserProfile user) {
        user.getEnforcementDetectors().clear();
        user.getEnforcementDetectors().add(new EnforcementDetector(EnforcementDetector.DetectorType.STATUS_CODE_EQUALS, "401"));
        user.getEnforcementDetectors().add(new EnforcementDetector(EnforcementDetector.DetectorType.STATUS_CODE_EQUALS, "403"));
        user.getEnforcementDetectors().add(new EnforcementDetector(EnforcementDetector.DetectorType.BODY_CONTAIN, "unauthorized"));
        user.getEnforcementDetectors().add(new EnforcementDetector(EnforcementDetector.DetectorType.BODY_CONTAIN, "access denied"));
    }

    public synchronized void commitState() {
        try {
            extensionData.setBoolean(KEY_INTERCEPT_ENABLED, interceptEnabled);
            extensionData.setBoolean(KEY_CHECK_UNAUTH, checkUnauthenticated);
            extensionData.setBoolean(KEY_SAFE_METHODS_ONLY, safeMethodsOnly);
            extensionData.setBoolean(KEY_PREVENT_304, prevent304);
            extensionData.setBoolean(KEY_IGNORE_304, ignore304);
            extensionData.setBoolean(KEY_INTERCEPT_PROXY, interceptProxy);
            extensionData.setBoolean(KEY_INTERCEPT_REPEATER, interceptRepeater);
            extensionData.setBoolean(KEY_IGNORE_EXTENSIONS, ignoreExtensions);
            extensionData.setInteger(KEY_AUTO_INCREMENT, requestCounter.get());

            extensionData.setString(KEY_USERS, objectMapper.writeValueAsString(userProfiles));
            extensionData.setString(KEY_FILTERS, objectMapper.writeValueAsString(interceptionFilters));
            extensionData.setString(KEY_UNAUTH_DETECTORS, objectMapper.writeValueAsString(unauthDetectors));
            extensionData.setString(KEY_LOGS, objectMapper.writeValueAsString(logEntries));
        } catch (Exception e) {
            api.logging().logToError("Failed to persist Autorize state to project file: " + e.getMessage());
        }
    }

    public synchronized int recordOriginalTraffic(HttpRequestResponse original) {
        originalTrafficList.add(original);
        return originalTrafficList.size() - 1;
    }

    public synchronized int recordUnauthTraffic(HttpRequestResponse unauth) {
        unauthTrafficList.add(unauth);
        return unauthTrafficList.size() - 1;
    }

    public synchronized int recordUserTraffic(String userId, HttpRequestResponse userTraffic) {
        PersistedList<HttpRequestResponse> list = getUserTrafficStore(userId);
        list.add(userTraffic);
        return list.size() - 1;
    }

    public HttpRequestResponse getOriginalTraffic(int index) {
        if (index >= 0 && index < originalTrafficList.size()) {
            return originalTrafficList.get(index);
        }
        return null;
    }

    public HttpRequestResponse getUnauthTraffic(int index) {
        if (index >= 0 && index < unauthTrafficList.size()) {
            return unauthTrafficList.get(index);
        }
        return null;
    }

    public HttpRequestResponse getUserTraffic(String userId, int index) {
        PersistedList<HttpRequestResponse> list = userTrafficLists.get(userId);
        if (list != null && index >= 0 && index < list.size()) {
            return list.get(index);
        }
        return null;
    }

    public int getNextRequestId() {
        return requestCounter.getAndIncrement();
    }

    public void appendLogEntry(LogEntry entry) {
        logEntries.add(entry);
        commitState();
    }

    public void clearAllLogs() {
        logEntries.clear();
        originalTrafficList.clear();
        unauthTrafficList.clear();
        for (PersistedList<HttpRequestResponse> list : userTrafficLists.values()) {
            list.clear();
        }
        requestCounter.set(1);
        commitState();
    }

    private boolean getBoolean(String key, boolean defaultValue) {
        Boolean b = extensionData.getBoolean(key);
        return b != null ? b : defaultValue;
    }

    // Getters and Setters
    public List<UserProfile> getUserProfiles() { return userProfiles; }
    public List<InterceptionFilter> getInterceptionFilters() { return interceptionFilters; }
    public List<EnforcementDetector> getUnauthDetectors() { return unauthDetectors; }
    public List<LogEntry> getLogEntries() { return logEntries; }

    public boolean isInterceptEnabled() { return interceptEnabled; }
    public void setInterceptEnabled(boolean interceptEnabled) {
        this.interceptEnabled = interceptEnabled;
        commitState();
    }

    public boolean isCheckUnauthenticated() { return checkUnauthenticated; }
    public void setCheckUnauthenticated(boolean checkUnauthenticated) {
        this.checkUnauthenticated = checkUnauthenticated;
        commitState();
    }

    public boolean isSafeMethodsOnly() { return safeMethodsOnly; }
    public void setSafeMethodsOnly(boolean safeMethodsOnly) {
        this.safeMethodsOnly = safeMethodsOnly;
        commitState();
    }

    public boolean isPrevent304() { return prevent304; }
    public void setPrevent304(boolean prevent304) {
        this.prevent304 = prevent304;
        commitState();
    }

    public boolean isIgnore304() { return ignore304; }
    public void setIgnore304(boolean ignore304) {
        this.ignore304 = ignore304;
        commitState();
    }

    public boolean isInterceptProxy() { return interceptProxy; }
    public void setInterceptProxy(boolean interceptProxy) {
        this.interceptProxy = interceptProxy;
        commitState();
    }

    public boolean isInterceptRepeater() { return interceptRepeater; }
    public void setInterceptRepeater(boolean interceptRepeater) {
        this.interceptRepeater = interceptRepeater;
        commitState();
    }

    public boolean isIgnoreExtensions() { return ignoreExtensions; }
    public void setIgnoreExtensions(boolean ignoreExtensions) {
        this.ignoreExtensions = ignoreExtensions;
        commitState();
    }

    public synchronized void removeLogEntries(List<LogEntry> entries) {
        if (entries == null || entries.isEmpty()) return;
        logEntries.removeAll(entries);
        commitState();
    }

    public synchronized void importConfigBundle(AutorizeConfigBundle bundle) {
        if (bundle == null) return;
        if (bundle.getUserProfiles() != null && !bundle.getUserProfiles().isEmpty()) {
            userProfiles.clear();
            userProfiles.addAll(bundle.getUserProfiles());
            for (UserProfile u : userProfiles) {
                getUserTrafficStore(u.getId());
            }
        }
        if (bundle.getInterceptionFilters() != null) {
            interceptionFilters.clear();
            interceptionFilters.addAll(bundle.getInterceptionFilters());
        }
        if (bundle.getUnauthDetectors() != null) {
            unauthDetectors.clear();
            unauthDetectors.addAll(bundle.getUnauthDetectors());
        }
        if (bundle.getCheckUnauthenticated() != null) this.checkUnauthenticated = bundle.getCheckUnauthenticated();
        if (bundle.getSafeMethodsOnly() != null) this.safeMethodsOnly = bundle.getSafeMethodsOnly();
        if (bundle.getPrevent304() != null) this.prevent304 = bundle.getPrevent304();
        if (bundle.getIgnore304() != null) this.ignore304 = bundle.getIgnore304();
        if (bundle.getInterceptProxy() != null) this.interceptProxy = bundle.getInterceptProxy();
        if (bundle.getInterceptRepeater() != null) this.interceptRepeater = bundle.getInterceptRepeater();
        if (bundle.getIgnoreExtensions() != null) this.ignoreExtensions = bundle.getIgnoreExtensions();
        commitState();
    }

    public AutorizeConfigBundle exportConfigBundle() {
        AutorizeConfigBundle bundle = new AutorizeConfigBundle();
        bundle.setUserProfiles(new ArrayList<>(userProfiles));
        bundle.setInterceptionFilters(new ArrayList<>(interceptionFilters));
        bundle.setUnauthDetectors(new ArrayList<>(unauthDetectors));
        bundle.setCheckUnauthenticated(checkUnauthenticated);
        bundle.setSafeMethodsOnly(safeMethodsOnly);
        bundle.setPrevent304(prevent304);
        bundle.setIgnore304(ignore304);
        bundle.setInterceptProxy(interceptProxy);
        bundle.setInterceptRepeater(interceptRepeater);
        bundle.setIgnoreExtensions(ignoreExtensions);
        return bundle;
    }
}
