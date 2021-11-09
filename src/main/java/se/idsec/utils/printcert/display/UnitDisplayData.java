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
package se.idsec.utils.printcert.display;

import se.idsec.utils.printcert.enums.SupportedExtension;

import java.util.List;

/**
 *
 * @author stefan
 */
public class UnitDisplayData {
    String name;
    String id;
    int sequence;
    UnitType type;
    boolean criticality;
    List<String[]> dataArray;
    String freeText;
    boolean structured;
    boolean hasPrefix;

    public UnitDisplayData(UnitType type) {
        this.type = type;
    }

    public UnitDisplayData(String name, String id, int sequence, boolean criticality, List<String[]> dataArray) {
        this.type = UnitType.extension;
        this.name = name;
        this.id = id;
        this.sequence = sequence;
        this.criticality = criticality;
        this.dataArray = dataArray;
        this.structured=true;
    }
    public UnitDisplayData(SupportedExtension ext, int sequence, boolean criticality, List<String[]> dataArray) {
        this.type = UnitType.extension;
        this.name = ext.getName();
        this.id = ext.getOid().getId();
        this.sequence = sequence;
        this.criticality = criticality;
        this.dataArray = dataArray;
        this.structured=true;
    }
    public UnitDisplayData(SupportedExtension ext, int sequence, boolean criticality, String freeText, boolean hasPrefix) {
        this.type = UnitType.extension;
        this.name = ext.getName();
        this.id = ext.getOid().getId();
        this.sequence = sequence;
        this.criticality = criticality;
        this.freeText = freeText;
        this.hasPrefix=hasPrefix;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public int getSequence() {
        return sequence;
    }

    public void setSequence(int sequence) {
        this.sequence = sequence;
    }

    public UnitType getType() {
        return type;
    }

    public void setType(UnitType type) {
        this.type = type;
    }

    public boolean isCriticality() {
        return criticality;
    }

    public void setCriticality(boolean criticality) {
        this.criticality = criticality;
    }

    public List<String[]> getDataArray() {
        return dataArray;
    }

    public void setDataArray(List<String[]> dataArray) {
        this.dataArray = dataArray;
    }

    public String getFreeText() {
        return freeText;
    }

    public void setFreeText(String freeText) {
        this.freeText = freeText;
    }

    public boolean isStructured() {
        return structured;
    }

    public void setStructured(boolean structured) {
        this.structured = structured;
    }

    public boolean isHasPrefix() {
        return hasPrefix;
    }

    public void setHasPrefix(boolean hasPrefix) {
        this.hasPrefix = hasPrefix;
    }
    
    

    
}
