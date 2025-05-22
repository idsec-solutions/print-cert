/*
 * Copyright 2021-2025 IDsec Solutions AB
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


import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * HTML element abstract class
 */
public abstract class HtmlElement {

    String tag = "", text = "";
    List<HtmlElement> objects = new ArrayList<HtmlElement>();
    List<Attribute> attributes = new ArrayList<Attribute>();
    List<Style> styles = new ArrayList<Style>();
    List<Action> action = new ArrayList<Action>();
    /**
     * System line separator string
     */
    public static final String LF = System.getProperty("line.separator");

    /**
     * Generate a string representation of the Html element including all it's
     * child elements
     *
     * @return html string
     */
    @Override
    public String toString() {
        return toString(false);
    }

    /**
     * Generate a string representation of the Html element including all it's
     * child elements
     *
     * @param lineBreak include line breaks in the html data for increased
     * readability
     * @return html string
     */
    public String toString(boolean lineBreak) {
        StringBuilder b = new StringBuilder();
        boolean tagged = false;
        if (tag.length() > 0) {
            tagged = true;
        }
        if (tagged) {
            b.append("<").append(tag);
            for (Attribute attribute : attributes) {
                b.append(attribute.toString());
            }

            if (!styles.isEmpty()) {
                b.append(" style='");
                Iterator<Style> its = styles.iterator();
                while (its.hasNext()) {
                    Style style = its.next();
                    b.append(style.toString());
                    if (its.hasNext()) {
                        b.append("; ");
                    }
                }
                b.append("'");
            }

            if (!action.isEmpty()) {
                b.append(getActions(action));
            }
            if (text.length() == 0 && objects.isEmpty()) {
                b.append("/>");
                b.append(lineBreak ? LF : "");
            } else {
                b.append(">");
                // conditions for line break after first tag
                if (lineBreak && !objects.isEmpty() && text.length() == 0) {
                    if (!(objects.get(0) instanceof TextObject)) {
                        b.append(LF);
                    }
                }
                b.append(text);
                for (HtmlElement html : objects) {
                    b.append(html.toString(lineBreak));
                }
                b.append("</").append(tag).append(">");
                b.append(lineBreak ? LF : "");
            }
        } else {
            b.append(text);
        }
        return b.toString();
    }

    private String getActions(List<Action> action) {
        StringBuilder b = new StringBuilder();
        for (Action act : action) {
            b.append(act.toString());
        }
        return b.toString();
    }

    /**
     * Sets text content within the html element
     *
     * @param text the text content
     */
    public HtmlElement setText(String text) {
        this.text = text;
        return this;

    }

    /**
     * Add a child html element to this html element
     *
     * @param element the HTML element to add
     * @return This element
     */
    public HtmlElement addHtmlElement(HtmlElement element) {
        objects.add(element);
        return this;
    }

    /**
     * Add a child html element to this html element
     *
     * @param element the HTML element to add
     * @return The added html element
     */
    public HtmlElement addNewHtmlElement(HtmlElement element) {
        objects.add(element);
        return element;
    }

    /**
     * Add style to html element
     *
     * @param type style type
     * @param value style value
     * @return This object
     */
    public HtmlElement addStyle(String type, String value) {
        styles.add(new Style(type, value));
        return this;
    }

    /**
     * Add attribute to html element
     *
     * @param type attribute name
     * @param value attribute value
     * @return This object
     */
    public HtmlElement addAttribute(String type, String value) {
        attributes.add(new Attribute(type, value));
        return this;
    }

    /**
     * Add javascript action to html element
     *
     * @param event toggle event (e.g. onclick)
     * @param function name of javscript function (not including parameter
     * brackets "()"
     * @param args Arguments for the javascript function
     * @return This object
     */
    public HtmlElement addAction(String event, String function, String[] args) {
        action.add(new Action(event, function, args));
        return this;
    }

    /**
     * Add javascript action to html element
     *
     * @param event toggle event (e.g. onclick)
     * @param function name of javscript function (not including parameter
     * brackets "()"
     * @param arg Argument for the javascript function
     * @return This object
     */
    public HtmlElement addAction(String event, String function, String arg) {
        action.add(new Action(event, function, new String[]{arg}));
        return this;
    }

    /**
     * Add javascript action to html element
     *
     * @param event toggle event (e.g. onclick)
     * @param function name of javscript function (not including parameter
     * brackets "()"
     * @return This objecxt
     */
    public HtmlElement addAction(String event, String function) {
        action.add(new Action(event, function, new String[]{}));
        return this;
    }

    private class Attribute {

        private String type, value;

        public Attribute(String type, String value) {
            this.type = type;
            this.value = value;
        }

        @Override
        public String toString() {
            StringBuilder b = new StringBuilder();
            if (value == null) {
                b.append(" ").append(type);
            } else {
                b.append(" ").append(type).append("='");
                b.append(value).append("'");
            }
            return b.toString();
        }
    }

    private class Style {

        public String type, value;

        public Style(String type, String value) {
            this.type = type;
            this.value = value;
        }

        @Override
        public String toString() {
            StringBuilder b = new StringBuilder();
            b.append(type).append(": ");
            b.append(value);
            return b.toString();
        }
    }

    public void setAction(List<Action> action) {
        this.action = action;
    }

    public void setAttributes(List<Attribute> attributes) {
        this.attributes = attributes;
    }

    public void setElements(List<HtmlElement> objects) {
        this.objects = objects;
    }

    public List<HtmlElement> getElements() {
        return objects;
    }

    public void setStyles(List<Style> styles) {
        this.styles = styles;
    }

    private class Action {

        public String event, function;
        public String[] args;

        public Action(String event, String function, String[] args) {
            this.event = event;
            this.function = function;
            this.args = args;
        }

        @Override
        public String toString() {
            StringBuilder b = new StringBuilder();
            b.append(" ").append(event).append("='");
            b.append(function).append("(");
            for (int i = 0; i < args.length; i++) {
                if (isNUmeric(args[i])) {
                    b.append(args[i]);
                } else {
                    b.append("\"").append(args[i]).append("\"");
                }
                if ((i + 1) < args.length) {
                    b.append(",");
                }
            }
            b.append(")'");
            return b.toString();
        }

        private boolean isNUmeric(String arg) {
            boolean numeric = true;
            byte[] bytes = arg.getBytes();
            for (byte b : bytes) {
                int c = b;
                if (c < 48 || c > 57) {  //if a char is outside of the numerif cange 0-9
                    numeric = false;
                }
            }
            return numeric;
        }
    }
}
