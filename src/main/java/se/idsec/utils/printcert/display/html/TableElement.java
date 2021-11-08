/*
 * Copyright (c) 2021. IDsec Solutions AB (IDsec)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.utils.printcert.display.html;

import java.util.List;

/**
 * HTML table element
 */
public class TableElement extends HtmlElement {

    public TableElement() {
        this("", "");
    }

    public TableElement(String className) {
        this(className, "");
    }

    public TableElement(String className, String id) {
        this.tag = "table";
        if (className.length() > 0) {
            this.addAttribute("class", className);
        }
        if (id.length() > 0) {
            this.addAttribute("id", id);
        }
    }

    /**
     * Adds a table row to a HTML table
     *
     * @param cells an array of table cell data strings. Each string will be
     * placed in a separate table cell from left to right
     * @param classNames The first string in the array will be used as class for
     * the table row. additional strings in the array will be used as classes
     * for each table cell from left to right. If the number of strings is <
     * cells+1, then the last cells will have no class assigned. A String value
     * of "" causes no class to be added to the corresponding cell/row @param
     * colspan the column span for the last table cell @param show false of this
     * table row should be hidden, otherwise true
     */
    public void addRow(String[] cells, String[] classNames, int colspan, boolean[] show, String id) {
        String trClass = classNames.length > 0 ? classNames[0] : "";
        TableRowElement tr = new TableRowElement(trClass);
        if (id != null) {
            tr.addAttribute("id", id);
        }

        int maxTdClass = classNames.length - 1;

        for (int i = 0; i < cells.length; i++) {
            String cell = cells[i];
            int cs = (i == cells.length - 1) ? colspan : 1;
            String cls = (i < maxTdClass) ? classNames[i + 1] : "";
            TableCellElement td = new TableCellElement(cell, cs, cls);
            try {
                if (!show[i]) {
                    td.addStyle("display", "none");
                }
            } catch (Exception ex) {
            }
            tr.addHtmlElement(td);
        }
        addHtmlElement(tr);
    }

    public void addRow(String[] cells, String className, int colspan, boolean[] show) {
        addRow(cells, new String[]{className}, colspan, show, null);
    }

    public void addRow(String[] cells, String className) {
        addRow(cells, new String[]{className}, 1, new boolean[]{true}, null);
    }

    public void addRow(String cell, String[] classNames, int colspan, boolean show) {
        addRow(new String[]{cell}, classNames, colspan, new boolean[]{show}, null);
    }

    public void addRow(String cell, String className, int colspan, boolean show) {
        addRow(new String[]{cell}, new String[]{className}, colspan, new boolean[]{show}, null);
    }

    public void addRow(String cell, String className, int colspan, boolean show, String id) {
        addRow(new String[]{cell}, new String[]{className}, colspan, new boolean[]{show}, id);
    }

    public void addRow(String cell, String className) {
        addRow(new String[]{cell}, new String[]{className}, 1, new boolean[]{true}, null);
    }

    public void addRow(String[] cells, int colspan) {
        addRow(cells, "", colspan, new boolean[]{true});
    }

    public void addRow(String[] cells, String[] classNames, boolean[] show) {
        addRow(cells, classNames, 1, show, null);
    }

    public void addRow(String[] cells, String[] classNames) {
        addRow(cells, classNames, new boolean[]{true});
    }

    public void addRow(String[] cells) {
        addRow(cells, 1);
    }

    public void addRow(String cell, int colspan) {
        addRow(new String[]{cell}, colspan);
    }

    public void addRow(String cell) {
        addRow(new String[]{cell}, 1);
    }

    public TableRowElement getLastTableRow() {
        TableRowElement tr;
        List<HtmlElement> elements = getElements();
        if (elements.isEmpty()) {
            tr = new TableRowElement();
            addHtmlElement(tr);
            return tr;
        }
        HtmlElement he = elements.get(elements.size() - 1);
        if (he instanceof TableRowElement) {
            tr = (TableRowElement) he;
        } else {
            tr = new TableRowElement();
            addHtmlElement(tr);
        }
        return tr;
    }
}
