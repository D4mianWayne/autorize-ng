package com.autorize.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AutorizeConfigBundle {

    @JsonProperty("version")
    private String version = "0.1.0";

    @JsonProperty("userProfiles")
    private List<UserProfile> userProfiles;

    @JsonProperty("interceptionFilters")
    private List<InterceptionFilter> interceptionFilters;

    @JsonProperty("unauthDetectors")
    private List<EnforcementDetector> unauthDetectors;

    @JsonProperty("checkUnauthenticated")
    private Boolean checkUnauthenticated;

    @JsonProperty("safeMethodsOnly")
    private Boolean safeMethodsOnly;

    @JsonProperty("prevent304")
    private Boolean prevent304;

    @JsonProperty("ignore304")
    private Boolean ignore304;

    @JsonProperty("interceptProxy")
    private Boolean interceptProxy;

    @JsonProperty("interceptRepeater")
    private Boolean interceptRepeater;

    @JsonProperty("ignoreExtensions")
    private Boolean ignoreExtensions;

    public AutorizeConfigBundle() {}

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public List<UserProfile> getUserProfiles() { return userProfiles; }
    public void setUserProfiles(List<UserProfile> userProfiles) { this.userProfiles = userProfiles; }

    public List<InterceptionFilter> getInterceptionFilters() { return interceptionFilters; }
    public void setInterceptionFilters(List<InterceptionFilter> interceptionFilters) { this.interceptionFilters = interceptionFilters; }

    public List<EnforcementDetector> getUnauthDetectors() { return unauthDetectors; }
    public void setUnauthDetectors(List<EnforcementDetector> unauthDetectors) { this.unauthDetectors = unauthDetectors; }

    public Boolean getCheckUnauthenticated() { return checkUnauthenticated; }
    public void setCheckUnauthenticated(Boolean checkUnauthenticated) { this.checkUnauthenticated = checkUnauthenticated; }

    public Boolean getSafeMethodsOnly() { return safeMethodsOnly; }
    public void setSafeMethodsOnly(Boolean safeMethodsOnly) { this.safeMethodsOnly = safeMethodsOnly; }

    public Boolean getPrevent304() { return prevent304; }
    public void setPrevent304(Boolean prevent304) { this.prevent304 = prevent304; }

    public Boolean getIgnore304() { return ignore304; }
    public void setIgnore304(Boolean ignore304) { this.ignore304 = ignore304; }

    public Boolean getInterceptProxy() { return interceptProxy; }
    public void setInterceptProxy(Boolean interceptProxy) { this.interceptProxy = interceptProxy; }

    public Boolean getInterceptRepeater() { return interceptRepeater; }
    public void setInterceptRepeater(Boolean interceptRepeater) { this.interceptRepeater = interceptRepeater; }

    public Boolean getIgnoreExtensions() { return ignoreExtensions; }
    public void setIgnoreExtensions(Boolean ignoreExtensions) { this.ignoreExtensions = ignoreExtensions; }
}
