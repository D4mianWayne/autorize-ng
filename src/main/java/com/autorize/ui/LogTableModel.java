package com.autorize.ui;

import com.autorize.model.EnforcementStatus;
import com.autorize.model.LogEntry;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class LogTableModel extends AbstractTableModel {

    private final PersistenceManager persistenceManager;

    public LogTableModel(PersistenceManager persistenceManager) {
        this.persistenceManager = persistenceManager;
    }

    @Override
    public int getRowCount() {
        return persistenceManager.getLogEntries().size();
    }

    @Override
    public int getColumnCount() {
        // Base columns: ID (0), Method (1), URL (2), Orig Len (3), Unauth Len (4), Unauth Status (5)
        // Plus 2 columns per User: Modif Len, Status
        return 6 + (persistenceManager.getUserProfiles().size() * 2);
    }

    @Override
    public String getColumnName(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> "ID";
            case 1 -> "Method";
            case 2 -> "URL";
            case 3 -> "Orig. Len";
            case 4 -> "Unauth. Len";
            case 5 -> "Unauth. Status";
            default -> {
                int userIdx = (columnIndex - 6) / 2;
                int colType = (columnIndex - 6) % 2;
                List<UserProfile> users = persistenceManager.getUserProfiles();
                if (userIdx < users.size()) {
                    String uName = users.get(userIdx).getName();
                    yield colType == 0 ? uName + " Modif. Len" : uName + " Authz. Status";
                }
                yield "";
            }
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        if (columnIndex == 0 || columnIndex == 3 || columnIndex == 4) return Integer.class;
        if (columnIndex == 1 || columnIndex == 2) return String.class;
        if (columnIndex == 5) return EnforcementStatus.class;

        int colType = (columnIndex - 6) % 2;
        return colType == 0 ? Integer.class : EnforcementStatus.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        List<LogEntry> logs = persistenceManager.getLogEntries();
        if (rowIndex < 0 || rowIndex >= logs.size()) return "";
        LogEntry log = logs.get(rowIndex);

        return switch (columnIndex) {
            case 0 -> log.getId();
            case 1 -> log.getMethod();
            case 2 -> log.getUrl();
            case 3 -> log.getOriginalLength();
            case 4 -> log.getUnauthLength();
            case 5 -> log.getUnauthStatus();
            default -> {
                int userIdx = (columnIndex - 6) / 2;
                int colType = (columnIndex - 6) % 2;
                List<UserProfile> users = persistenceManager.getUserProfiles();
                if (userIdx < users.size()) {
                    String userId = users.get(userIdx).getId();
                    LogEntry.UserResult res = log.getUserResult(userId);
                    if (res != null) {
                        yield colType == 0 ? res.getUserLength() : res.getStatus();
                    } else {
                        yield colType == 0 ? 0 : EnforcementStatus.DISABLED;
                    }
                }
                yield "";
            }
        };
    }

    public LogEntry getEntryAt(int rowIndex) {
        List<LogEntry> logs = persistenceManager.getLogEntries();
        if (rowIndex >= 0 && rowIndex < logs.size()) {
            return logs.get(rowIndex);
        }
        return null;
    }
}
