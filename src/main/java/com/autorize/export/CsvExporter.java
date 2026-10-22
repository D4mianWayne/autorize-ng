package com.autorize.export;

import com.autorize.model.LogEntry;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

public class CsvExporter {

    public static void exportToCsv(File targetFile, PersistenceManager persistenceManager) throws IOException {
        List<LogEntry> logs = persistenceManager.getLogEntries();
        List<UserProfile> users = persistenceManager.getUserProfiles();

        try (PrintWriter writer = new PrintWriter(new FileWriter(targetFile))) {
            StringBuilder header = new StringBuilder("ID,Method,URL,Orig_Len,Unauth_Len,Unauth_Status");
            for (UserProfile user : users) {
                header.append(",").append(escapeCsv(user.getName())).append("_Len");
                header.append(",").append(escapeCsv(user.getName())).append("_Status");
            }
            writer.println(header);

            for (LogEntry log : logs) {
                StringBuilder row = new StringBuilder();
                row.append(log.getId()).append(",");
                row.append(escapeCsv(log.getMethod())).append(",");
                row.append(escapeCsv(log.getUrl())).append(",");
                row.append(log.getOriginalLength()).append(",");
                row.append(log.getUnauthLength()).append(",");
                row.append(escapeCsv(log.getUnauthStatus().getDisplayName()));

                for (UserProfile user : users) {
                    LogEntry.UserResult ur = log.getUserResult(user.getId());
                    if (ur != null) {
                        row.append(",").append(ur.getUserLength());
                        row.append(",").append(escapeCsv(ur.getStatus().getDisplayName()));
                    } else {
                        row.append(",0,Disabled");
                    }
                }
                writer.println(row);
            }
        }
    }

    private static String escapeCsv(String val) {
        if (val == null) return "";
        if (val.contains(",") || val.contains("\"") || val.contains("\n")) {
            return "\"" + val.replace("\"", "\"\"") + "\"";
        }
        return val;
    }
}
