package com.autorize.ui;

import com.autorize.model.EnforcementStatus;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

public class StatusCellRenderer extends DefaultTableCellRenderer {

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                                                   boolean hasFocus, int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (value instanceof EnforcementStatus status) {
            setText(status.getDisplayName());
            if (!isSelected) {
                c.setBackground(status.getBackgroundColor());
                c.setForeground(Color.BLACK);
            }
            setFont(getFont().deriveFont(Font.BOLD));
            setHorizontalAlignment(SwingConstants.CENTER);
        } else if (value instanceof String str) {
            EnforcementStatus status = EnforcementStatus.fromString(str);
            if (!isSelected) {
                c.setBackground(status.getBackgroundColor());
                c.setForeground(Color.BLACK);
            }
            setHorizontalAlignment(SwingConstants.CENTER);
        } else {
            setHorizontalAlignment(SwingConstants.LEFT);
            if (!isSelected) {
                c.setBackground(table.getBackground());
                c.setForeground(table.getForeground());
            }
        }

        if (isSelected) {
            c.setBackground(new Color(186, 215, 255));
            c.setForeground(Color.BLACK);
        }

        return c;
    }
}
