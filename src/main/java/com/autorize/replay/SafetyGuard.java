package com.autorize.replay;

import burp.api.montoya.http.message.requests.HttpRequest;
import com.autorize.model.HttpMethod;
import com.autorize.persistence.PersistenceManager;

public class SafetyGuard {

    private final PersistenceManager persistenceManager;

    public SafetyGuard(PersistenceManager persistenceManager) {
        this.persistenceManager = persistenceManager;
    }

    public boolean isSafeToReplay(HttpRequest request) {
        if (!persistenceManager.isSafeMethodsOnly()) {
            return true;
        }

        HttpMethod method = HttpMethod.fromString(request.method());
        return method.isSafe();
    }
}
