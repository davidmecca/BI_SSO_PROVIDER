package com.infa.sso.common;

import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class StringUtilities {

	public static String getObjectStringValue(Object obj) {

		try {
			if (obj != null) {
				if (obj.getClass().equals(String.class))
					return ((String) obj).trim();

				if (obj.getClass().equals(Integer.class))
					return String.valueOf((Integer) obj);

				if (obj.getClass().equals(BigDecimal.class))
					return ((BigDecimal) obj).toString().trim();

				if (obj.getClass().equals(Number.class))
					return ((Number) obj).toString().trim();

				if (obj.getClass().equals(Date.class)) {

					DateFormat df = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss z");
					String dt = df.format((Date) obj);
					return dt;
				}
				if (obj.getClass().equals(Boolean.class))
					return Boolean.toString((Boolean) obj).trim();
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return "";

	}

	public static String stackTraceToString(StackTraceElement[] stack) {
		StringBuilder sb = new StringBuilder();
		for (StackTraceElement s : stack) {
			sb.append(s.toString() + "\n\t\t");
		}
		return sb.toString();
	}

	public static Date parseDate(String dateIn) throws ParseException {

		SimpleDateFormat formatter = new SimpleDateFormat("MM/dd/yyyy");

		Date date = null;

		if (dateIn != null && dateIn.trim().length() > 0)
			date = formatter.parse(dateIn);

		return date;
	}

	public static Date parseDate(String format, String dateIn) throws ParseException {

		Date date = null;

		if (dateIn != null && !dateIn.isEmpty()) {
			SimpleDateFormat formatter = new SimpleDateFormat(format);

			if (dateIn != null && dateIn.trim().length() > 0)
				date = formatter.parse(dateIn);

		}

		return date;
	}

	public static String padRight(String s, int n) {
		return String.format("%1$-" + n + "s", s);
	}

	public static String padLeft(String s, int n) {
		return String.format("%1$" + n + "s", s);
	}

	public static long formatTimeToSeconds(long startTime, long endTime) {

		long duration;
		long formattedTime = 0;
		if ((endTime > 0) && (endTime > startTime)) {
			duration = endTime - startTime;
			formattedTime = TimeUnit.SECONDS.convert(duration, TimeUnit.NANOSECONDS);

		}

		return formattedTime;

	}

	public static double formatMillisecondsToSeconds(long startTime, long endTime) {

		return (endTime - startTime) / 1000.0;

	}

	public static double formatTimeToMilliSeconds(long startTime, long endTime) {

		long duration;
		double formattedTime = 0.0;
		if ((endTime > 0) && (endTime > startTime)) {
			duration = endTime - startTime;
			formattedTime = TimeUnit.MILLISECONDS.convert(duration, TimeUnit.NANOSECONDS) / 1000.00;

		}

		return formattedTime;

	}

	public static String formatTimeDiffInSeconds(long startTime, long endTime) {
		DecimalFormat df = new DecimalFormat("00");
		double diff = endTime - startTime;
		StringBuilder sb = new StringBuilder(10);
		sb.append((diff) / 1000);
		sb.append(".");
		sb.append(df.format(diff % 1000));

		return sb.toString();

	}

	public static String formatTimeDiffInSeconds(long duration) {
		DecimalFormat df = new DecimalFormat("000");
		StringBuilder sb = new StringBuilder(10);
		sb.append(duration / 1000);
		sb.append(".");
		sb.append(df.format(duration % 1000));

		return sb.toString();

	}

	public static String formatTimeInSeconds(long time) {
		DecimalFormat df = new DecimalFormat("000");
		StringBuilder sb = new StringBuilder(10);
		sb.append(time / 1000);
		sb.append(".");
		sb.append(df.format(time % 1000));

		return sb.toString();

	}

	public static boolean isValidDate(String inValue, String inFormat) {

		SimpleDateFormat sdf = new SimpleDateFormat(inFormat);
		try {
			sdf.parse(inValue);
			return true;
		} catch (ParseException pe) {
		}

		return false;

	}

	public static String formatDateString(String dateIn) {

		SimpleDateFormat formatter = new SimpleDateFormat("YYYY-MM-DD");

		String dateStr = null;

		try {
			if (dateIn != null && dateIn.trim().length() > 0)
				dateStr = formatter.format(formatter.parse(dateIn));
		} catch (ParseException pe) {
		}

		return dateStr;
	}

	public static String formatDateString(String format, String dateIn) {

		if (format == null || format.isEmpty())
			format = "YYYY-MM-DD";

		SimpleDateFormat formatter = new SimpleDateFormat(format);

		String dateStr = null;

		try {
			if (dateIn != null && dateIn.trim().length() > 0)
				dateStr = formatter.format(formatter.parse(dateIn));
		} catch (ParseException pe) {
		}

		return dateStr;
	}

	public static boolean isEmpty(String value) {
		if (value == null || value.length() == 0)
			return true;
		else
			return false;
	}

	public static String removeNonPrintChars(String s) {

		if (s != null && s.length() > 0)
			return s.trim().replaceAll("[\\p{Cntrl}&&[^\r\n\t]]", "");
		else
			return s;
	}

}
