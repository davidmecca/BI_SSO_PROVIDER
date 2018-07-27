//=====================================================================
// project:   Informatica MDM Hub
//---------------------------------------------------------------------
// copyright: Informatica (c) 2003-2016.  All rights reserved.
//=====================================================================

package com.infa.sso.common;

import java.nio.charset.StandardCharsets;
import javax.xml.bind.DatatypeConverter;

public class Base64Tool {

    private Base64Tool(){
    }

    public static String encode(String value) {
        return  encode(value.getBytes(StandardCharsets.UTF_8)); // use "utf-8" if java 6
    }

    public static String encode(byte[] value) {
        return  DatatypeConverter.printBase64Binary(value);
    }

    public static String decode(String value) {
        byte[] decodedValue = decodeBytes(value);
        return new String(decodedValue, StandardCharsets.UTF_8); // use "utf-8" if java 6
    }
    public static byte[] decodeBytes(String value) {
        return  DatatypeConverter.parseBase64Binary(value);
    }
}
