package com.autorize.export;

import com.autorize.model.EnforcementStatus;
import com.autorize.model.LogEntry;
import com.autorize.model.UserProfile;
import com.autorize.persistence.PersistenceManager;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.List;

public class HtmlExporter {

    public static void exportToHtml(File targetFile, PersistenceManager persistenceManager) throws IOException {
        List<LogEntry> logs = persistenceManager.getLogEntries();
        List<UserProfile> users = persistenceManager.getUserProfiles();

        try (PrintWriter writer = new PrintWriter(new FileWriter(targetFile))) {
            writer.println("<!DOCTYPE html>");
            writer.println("<html lang=\"en\"><head><meta charset=\"UTF-8\">");
            writer.println("<title>Autorize Next-Gen Security Report</title>");
            writer.println("<style>");
            writer.println("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 2rem; }");
            writer.println("h1 { color: #38bdf8; }");
            writer.println("table { width: 100%; border-collapse: collapse; margin-top: 1rem; background: #1e293b; border-radius: 8px; overflow: hidden; }");
            writer.println("th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }");
            writer.println("th { background: #0f172a; color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }");
            writer.println(".badge { padding: 4px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; display: inline-block; }");
            writer.println(".badge-bypassed { background: #ef4444; color: #fff; }");
            writer.println(".badge-enforced { background: #22c55e; color: #fff; }");
            writer.println(".badge-ambiguous { background: #f59e0b; color: #fff; }");
            writer.println(".badge-disabled { background: #64748b; color: #fff; }");
            writer.println("</style></head><body>");

            writer.println("<h1>Autorize Next-Gen: Authorization Audit Report</h1>");
            writer.println("<p>Generated at: " + Instant.now() + " | Total Endpoints Tested: " + logs.size() + "</p>");

            writer.println("<table><thead><tr>");
            writer.println("<th>ID</th><th>Method</th><th>URL</th><th>Orig Len</th><th>Unauth Status</th>");
            for (UserProfile user : users) {
                writer.println("<th>" + escape(user.getName()) + " Status</th>");
            }
            writer.println("</tr></thead><tbody>");

            for (LogEntry log : logs) {
                writer.println("<tr>");
                writer.println("<td>" + log.getId() + "</td>");
                writer.println("<td><strong>" + escape(log.getMethod()) + "</strong></td>");
                writer.println("<td>" + escape(log.getUrl()) + "</td>");
                writer.println("<td>" + log.getOriginalLength() + "</td>");
                writer.println("<td>" + renderBadge(log.getUnauthStatus()) + "</td>");

                for (UserProfile user : users) {
                    LogEntry.UserResult ur = log.getUserResult(user.getId());
                    if (ur != null) {
                        writer.println("<td>" + renderBadge(ur.getStatus()) + "</td>");
                    } else {
                        writer.println("<td><span class=\"badge badge-disabled\">-</span></td>");
                    }
                }
                writer.println("</tr>");
            }

            writer.println("</tbody></table></body></html>");
        }
    }

    private static String renderBadge(EnforcementStatus status) {
        if (status == null) return "<span class=\"badge badge-disabled\">N/A</span>";
        String cssClass = switch (status) {
            case BYPASSED -> "badge-bypassed";
            case ENFORCED -> "badge-enforced";
            case AMBIGUOUS -> "badge-ambiguous";
            default -> "badge-disabled";
        };
        return "<span class=\"badge " + cssClass + "\">" + status.getDisplayName() + "</span>";
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
